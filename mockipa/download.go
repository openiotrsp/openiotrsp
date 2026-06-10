package mockipa

import (
	"context"
	stdasn1 "encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	"github.com/damonto/euicc-go/driver"
	euichttp "github.com/damonto/euicc-go/http"
	"github.com/damonto/euicc-go/lpa"
	sgp22 "github.com/damonto/euicc-go/v2"
	"github.com/openiotrsp/openiotrsp/profiledownload"
)

// DownloadResult describes the device-side outcome that is reported to the eIM.
type DownloadResult struct {
	ProfileID string
	SMDP      string
	LiveSMDP  bool
	Offline   bool
	BPPBytes  []byte
}

// Downloader performs the IPA-side direct download.
type Downloader interface {
	Download(ctx context.Context, activation profiledownload.ActivationCode) (DownloadResult, error)
}

// OfflineDownloader is the CI-only fallback. It is intentionally not a signing proof.
type OfflineDownloader struct{}

// Download returns a deterministic success result without contacting an SM-DP+.
func (OfflineDownloader) Download(ctx context.Context, activation profiledownload.ActivationCode) (DownloadResult, error) {
	if err := ctx.Err(); err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{
		ProfileID: activation.ProfileID(),
		SMDP:      activation.SMDPAddress,
		Offline:   true,
	}, nil
}

// SysmocomDownloader validates that the public sysmocom SM-DP+ is reachable.
//
// A full signed download still requires an SGP.26 test eUICC/APDU channel. The
// mock IPA keeps this mode explicit so the offline fallback cannot be mistaken
// for signature validation.
type SysmocomDownloader struct {
	HTTPClient *http.Client
	FixtureZip string
	IMEI       string
}

// Download executes the ES9+ direct-download sequence against the live SM-DP+.
func (d SysmocomDownloader) Download(ctx context.Context, activation profiledownload.ActivationCode) (DownloadResult, error) {
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
	client := d.HTTPClient
	if client == nil {
		client = driver.NewHTTPClient(slog.Default(), 60*time.Second)
		client.Transport = statusBodyTransport{base: client.Transport}
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
	lpaClient := &lpa.Client{
		HTTP: &euichttp.Client{
			Client:               client,
			AdminProtocolVersion: "2.5.0",
		},
		APDU: euicc,
	}
	result, err := d.downloadProfile(ctx, lpaClient, euicc, &lpaActivation)
	if err != nil {
		return DownloadResult{}, err
	}
	profileID := activation.ProfileID()
	if result != nil && result.Notification != nil && len(result.Notification.ICCID) > 0 {
		profileID = result.Notification.ICCID.String()
	}
	var bppBytes []byte
	if bpp := euicc.BoundProfilePackage(); bpp != nil {
		bppBytes = bpp.Bytes()
	}
	return DownloadResult{
		ProfileID: profileID,
		SMDP:      activation.SMDPAddress,
		LiveSMDP:  true,
		BPPBytes:  bppBytes,
	}, nil
}

func (d SysmocomDownloader) downloadProfile(
	ctx context.Context,
	client *lpa.Client,
	euicc *SoftwareEUICC,
	activation *lpa.ActivationCode,
) (*sgp22.LoadBoundProfilePackageResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clientResponse, metadata, err := d.authenticateClient(client, activation)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, cancelSession(client, activation, clientResponse.TransactionID, sgp22.CancelSessionReasonPostponed, err)
	}
	serverResponse, err := client.PrepareDownload(activation.SMDP, &sgp22.PrepareDownloadRequest{
		TransactionID:    clientResponse.TransactionID,
		ProfileMetadata:  clientResponse.ProfileMetadata,
		Signed2:          clientResponse.Signed2,
		Signature2:       clientResponse.Signature2,
		Certificate:      clientResponse.Certificate,
		ConfirmationCode: []byte(activation.ConfirmationCode),
	})
	if err != nil {
		return nil, cancelSession(client, activation, clientResponse.TransactionID, sgp22.CancelSessionReasonPostponed, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, cancelSession(client, activation, serverResponse.TransactionID, sgp22.CancelSessionReasonPostponed, err)
	}
	smdpOID, err := parseActivationOID(activation.OID)
	if err != nil {
		return nil, cancelSession(client, activation, serverResponse.TransactionID, sgp22.CancelSessionReasonLoadBppExecutionError, err)
	}
	result, notification, err := euicc.LoadBoundProfilePackage(
		serverResponse.BoundProfilePackage,
		metadata,
		notificationAddress(metadata, activation.SMDP.Host),
		smdpOID,
	)
	if err != nil {
		return result, cancelSession(client, activation, serverResponse.TransactionID, sgp22.CancelSessionReasonLoadBppExecutionError, err)
	}
	if notification != nil {
		if err := client.HandleNotification(notification); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (d SysmocomDownloader) authenticateClient(
	client *lpa.Client,
	activation *lpa.ActivationCode,
) (*sgp22.ES9AuthenticateClientResponse, *sgp22.ProfileInfo, error) {
	initiateAuthenticationResponse, err := client.InitiateAuthentication(activation.SMDP)
	if err != nil {
		return nil, nil, err
	}
	imei, err := sgp22.NewIMEI(activation.IMEI)
	if err != nil {
		return nil, nil, err
	}
	response, err := client.AuthenticateClient(activation.SMDP, &sgp22.AuthenticateServerRequest{
		TransactionID: initiateAuthenticationResponse.TransactionID,
		Signed1:       initiateAuthenticationResponse.Signed1,
		Signature1:    initiateAuthenticationResponse.Signature1,
		UsedIssuer:    initiateAuthenticationResponse.UsedIssuer,
		Certificate:   initiateAuthenticationResponse.Certificate,
		IMEI:          imei,
		MatchingID:    []byte(activation.MatchingID),
	})
	if err != nil {
		return response, nil, err
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

func cancelSession(client *lpa.Client, activation *lpa.ActivationCode, transactionID []byte, reason sgp22.CancelSessionReason, err error) error {
	cancelSessionRequest, cancelErr := sgp22.InvokeAPDU(client.APDU, &sgp22.CancelSessionRequest{
		TransactionID: transactionID,
		Reason:        reason,
	})
	if cancelErr == nil {
		_, cancelErr = sgp22.InvokeHTTP(client.HTTP, activation.SMDP, cancelSessionRequest)
	}
	if cancelErr != nil {
		return fmt.Errorf("%w (cancel session error: %v)", err, cancelErr)
	}
	return err
}

func confirmationCodeRequired(tlv *bertlv.TLV) bool {
	if tlv == nil {
		return false
	}
	child := tlv.First(bertlv.Universal.Primitive(1))
	if child == nil {
		return false
	}
	var required bool
	_ = child.UnmarshalValue(primitive.UnmarshalBool(&required))
	return required
}

func notificationAddress(metadata *sgp22.ProfileInfo, fallback string) string {
	if metadata != nil {
		for _, config := range metadata.NotificationConfigurationInfo {
			if config != nil && config.ProfileManagementOperation == sgp22.NotificationEventInstall && strings.TrimSpace(config.Address) != "" {
				return strings.TrimSpace(config.Address)
			}
		}
	}
	return fallback
}

func parseActivationOID(value string) (stdasn1.ObjectIdentifier, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("mockipa: invalid SM-DP+ OID %q", value)
	}
	oid := make(stdasn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		arc, err := strconv.Atoi(part)
		if err != nil || arc < 0 {
			return nil, fmt.Errorf("mockipa: invalid SM-DP+ OID %q", value)
		}
		oid[i] = arc
	}
	if oid[0] > 2 || (oid[0] < 2 && oid[1] > 39) {
		return nil, fmt.Errorf("mockipa: invalid SM-DP+ OID %q", value)
	}
	return oid, nil
}

type statusBodyTransport struct {
	base http.RoundTripper
}

func (t statusBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil || response == nil || response.StatusCode < http.StatusBadRequest {
		return response, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
	if readErr != nil {
		return nil, fmt.Errorf("SM-DP+ returned %s and body read failed: %w", response.Status, readErr)
	}
	return nil, fmt.Errorf("SM-DP+ returned %s: %s", response.Status, strings.TrimSpace(string(body)))
}
