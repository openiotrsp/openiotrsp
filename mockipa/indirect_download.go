package mockipa

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/lpa"
	sgp22 "github.com/damonto/euicc-go/v2"
	"github.com/openiotrsp/openiotrsp/profiledownload"
)

// IndirectDownloader performs profile download with ES9+ relayed through the eIM.
type IndirectDownloader struct {
	Client     Client
	FixtureZip string
	IMEI       string
}

// Download executes indirect ES9+ profile download through the eIM relay.
func (d IndirectDownloader) Download(ctx context.Context, activation profiledownload.ActivationCode) (DownloadResult, error) {
	host := strings.TrimSpace(activation.SMDPAddress)
	if host == "" {
		return DownloadResult{}, fmt.Errorf("mockipa: missing SM-DP+ address")
	}
	fixture, err := LoadSGP26SoftwareFixture(d.FixtureZip)
	if err != nil {
		return DownloadResult{}, err
	}
	euicc, err := NewSoftwareEUICC(fixture)
	if err != nil {
		return DownloadResult{}, err
	}
	imei := strings.TrimSpace(d.IMEI)
	if imei == "" {
		imei = "490154203237518"
	}
	var lpaActivation lpa.ActivationCode
	if err := lpaActivation.UnmarshalText([]byte(activation.LPAString())); err != nil {
		return DownloadResult{}, err
	}
	lpaActivation.IMEI = imei

	result, err := d.downloadProfile(ctx, euicc, &lpaActivation)
	if err != nil {
		return DownloadResult{}, err
	}
	profileID := activation.ProfileID()
	if result != nil && result.Notification != nil && len(result.Notification.ICCID) > 0 {
		profileID = result.Notification.ICCID.String()
	}
	var bppBytes []byte
	var pir *bertlv.TLV
	if bpp := euicc.BoundProfilePackage(); bpp != nil {
		bppBytes = bpp.Bytes()
	}
	if pir = euicc.ProfileInstallationResult(); pir != nil {
		pir = pir.Clone()
	}
	return DownloadResult{
		ProfileID:                 profileID,
		SMDP:                      activation.SMDPAddress,
		LiveSMDP:                  true,
		BPPBytes:                  bppBytes,
		ProfileInstallationResult: pir,
	}, nil
}

func (d IndirectDownloader) downloadProfile(
	ctx context.Context,
	euicc *SoftwareEUICC,
	activation *lpa.ActivationCode,
) (*sgp22.LoadBoundProfilePackageResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clientResponse, metadata, err := d.authenticateClient(ctx, euicc, activation)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, d.cancelSession(ctx, euicc, clientResponse.TransactionID, sgp22.CancelSessionReasonPostponed, err)
	}
	prepareDownloadResponse, err := sgp22.InvokeAPDU(euicc, &sgp22.PrepareDownloadRequest{
		TransactionID:    clientResponse.TransactionID,
		ProfileMetadata:  clientResponse.ProfileMetadata,
		Signed2:          clientResponse.Signed2,
		Signature2:       clientResponse.Signature2,
		Certificate:      clientResponse.Certificate,
		ConfirmationCode: []byte(activation.ConfirmationCode),
	})
	if err != nil {
		return nil, d.cancelSession(ctx, euicc, clientResponse.TransactionID, sgp22.CancelSessionReasonPostponed, err)
	}
	if prepareDownloadResponse.Response == nil {
		return nil, d.cancelSession(ctx, euicc, clientResponse.TransactionID, sgp22.CancelSessionReasonPostponed, errors.New("mockipa: missing prepareDownload response"))
	}
	bppResponse, err := d.Client.Relay(ctx, buildGetBoundProfilePackageRelay(prepareDownloadResponse.Response))
	if err != nil {
		return nil, d.cancelSession(ctx, euicc, clientResponse.TransactionID, sgp22.CancelSessionReasonPostponed, err)
	}
	bppTLV, err := parseES9BoundProfilePackageResponse(bppResponse)
	if err != nil {
		return nil, d.cancelSession(ctx, euicc, clientResponse.TransactionID, sgp22.CancelSessionReasonLoadBppExecutionError, err)
	}
	smdpOID, err := parseActivationOID(activation.OID)
	if err != nil {
		return nil, d.cancelSession(ctx, euicc, clientResponse.TransactionID, sgp22.CancelSessionReasonLoadBppExecutionError, err)
	}
	result, notification, err := euicc.LoadBoundProfilePackage(
		bppTLV,
		metadata,
		notificationAddress(metadata, activation.SMDP.Host),
		smdpOID,
	)
	if err != nil {
		return result, d.cancelSession(ctx, euicc, clientResponse.TransactionID, sgp22.CancelSessionReasonLoadBppExecutionError, err)
	}
	if notification != nil && notification.PendingNotification != nil {
		if _, err := d.Client.Relay(ctx, buildHandleNotificationRelay(notification.PendingNotification)); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (d IndirectDownloader) authenticateClient(
	ctx context.Context,
	euicc *SoftwareEUICC,
	activation *lpa.ActivationCode,
) (*sgp22.ES9AuthenticateClientResponse, *sgp22.ProfileInfo, error) {
	initRelay, err := buildInitiateAuthenticationRelay(activation.SMDP.Host, euicc.EUICCInfo1())
	if err != nil {
		return nil, nil, err
	}
	initResponse, err := d.Client.Relay(ctx, initRelay)
	if err != nil {
		return nil, nil, err
	}
	transactionID, signed1, signature1, usedIssuer, certificate, err := parseES9InitiateAuthenticationResponse(initResponse)
	if err != nil {
		return nil, nil, err
	}
	imei, err := sgp22.NewIMEI(activation.IMEI)
	if err != nil {
		return nil, nil, err
	}
	authClientRequest, err := sgp22.InvokeAPDU(euicc, &sgp22.AuthenticateServerRequest{
		TransactionID: transactionID,
		Signed1:       signed1,
		Signature1:    signature1,
		UsedIssuer:    usedIssuer,
		Certificate:   certificate,
		IMEI:          imei,
		MatchingID:    []byte(activation.MatchingID),
	})
	if err != nil {
		return nil, nil, err
	}
	if authClientRequest.Response == nil {
		return nil, nil, errors.New("mockipa: missing authenticateServer response")
	}
	authResponse, err := d.Client.Relay(ctx, buildAuthenticateClientRelay(authClientRequest.Response))
	if err != nil {
		return nil, nil, err
	}
	txID, profileMetadata, signed2, signature2, smdpCert, err := parseES9AuthenticateClientResponse(authResponse)
	if err != nil {
		return nil, nil, err
	}
	response := &sgp22.ES9AuthenticateClientResponse{
		TransactionID:   txID,
		ProfileMetadata: profileMetadata,
		Signed2:         signed2,
		Signature2:      signature2,
		Certificate:     smdpCert,
	}
	metadata := new(sgp22.ProfileInfo)
	if err := metadata.UnmarshalBERTLV(response.ProfileMetadata); err != nil {
		return response, nil, err
	}
	if confirmationCodeRequired(response.Signed2) && activation.ConfirmationCode == "" {
		return response, nil, errors.New("mockipa: confirmation code is required")
	}
	return response, metadata, nil
}

func (d IndirectDownloader) cancelSession(
	ctx context.Context,
	euicc *SoftwareEUICC,
	transactionID []byte,
	reason sgp22.CancelSessionReason,
	err error,
) error {
	cancelRequest, cancelErr := sgp22.InvokeAPDU(euicc, &sgp22.CancelSessionRequest{
		TransactionID: transactionID,
		Reason:        reason,
	})
	if cancelErr == nil && cancelRequest.Response != nil {
		if _, relayErr := d.Client.Relay(ctx, buildCancelSessionRelay(cancelRequest.Response)); relayErr != nil {
			return fmt.Errorf("%w (cancel session relay error: %v)", err, relayErr)
		}
	}
	if cancelErr != nil {
		return fmt.Errorf("%w (cancel session error: %v)", err, cancelErr)
	}
	return err
}
