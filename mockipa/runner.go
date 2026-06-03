package mockipa

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/profiledownload"
)

// Runner polls ESipa, executes supported instructions, and uploads results.
type Runner struct {
	Client       Client
	Downloader   Downloader
	EID          []byte
	PollInterval time.Duration
	Once         bool
	Logger       *slog.Logger
}

// Run starts the mock IPA polling loop.
func (r Runner) Run(ctx context.Context) error {
	if len(r.EID) == 0 {
		return errors.New("mockipa: missing EID")
	}
	downloader := r.Downloader
	if downloader == nil {
		downloader = SysmocomDownloader{}
	}
	interval := r.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
	}

	for {
		if err := r.pollOnce(ctx, downloader, logger); err != nil {
			return err
		}
		if r.Once {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (r Runner) pollOnce(ctx context.Context, downloader Downloader, logger *slog.Logger) error {
	poll, err := r.Client.Poll(ctx, r.EID)
	if err != nil {
		return err
	}
	switch poll.Kind {
	case protocolasn1.GetEimPackageEuiccPackageRequest:
		return r.handleEUICCPackage(ctx, logger, poll.EuiccPackageRequest)
	case protocolasn1.GetEimPackageIpaEuiccDataRequest:
		return r.handleIpaEuiccDataRequest(ctx, logger, poll.IpaEuiccDataRequest)
	case protocolasn1.GetEimPackageProfileDownloadTriggerRequest:
		return r.handleProfileDownloadTrigger(ctx, downloader, logger, poll.ProfileDownloadTriggerRequest)
	case protocolasn1.GetEimPackageError:
		logger.Info("no eIM package available", "eid", hex.EncodeToString(r.EID))
		return nil
	default:
		logger.Info("unsupported eIM package for mock IPA", "kind", poll.Kind)
		return nil
	}
}

func (r Runner) handleIpaEuiccDataRequest(
	ctx context.Context,
	logger *slog.Logger,
	tlv *bertlv.TLV,
) error {
	var request protocolasn1.IpaEuiccDataRequest
	if err := request.UnmarshalBERTLV(tlv); err != nil {
		return err
	}
	response, err := IpaEuiccDataResponse(r.EID, &request)
	if err != nil {
		return err
	}
	if err := r.Client.UploadIpaEuiccDataResponse(ctx, r.EID, response); err != nil {
		return err
	}
	logger.Info("IPA eUICC data read complete", "eid", hex.EncodeToString(r.EID), "tagList", hex.EncodeToString(request.TagList))
	return nil
}

func (r Runner) handleEUICCPackage(
	ctx context.Context,
	logger *slog.Logger,
	request *protocolasn1.EuiccPackageRequest,
) error {
	result, operation, err := SuccessfulEUICCPackageResult(request)
	if err != nil {
		return err
	}
	if err := r.Client.UploadEUICCPackageResult(ctx, r.EID, result); err != nil {
		return err
	}
	logger.Info("eUICC package operation complete", "eid", hex.EncodeToString(r.EID), "operation", operation)
	return nil
}

func (r Runner) handleProfileDownloadTrigger(
	ctx context.Context,
	downloader Downloader,
	logger *slog.Logger,
	trigger *protocolasn1.ProfileDownloadTriggerRequest,
) error {
	if trigger == nil || trigger.ProfileDownloadData == nil {
		return errors.New("mockipa: malformed profile download trigger")
	}
	if trigger.ProfileDownloadData.Kind != protocolasn1.ProfileDownloadActivationCode {
		return errors.New("mockipa: only activation-code profile downloads are supported")
	}
	activation, err := profiledownload.ParseActivationCode(trigger.ProfileDownloadData.ActivationCode)
	if err != nil {
		return err
	}
	logger.Info("profile download trigger received", "smdp", activation.SMDPAddress, "matchingID", activation.MatchingID)
	result, err := downloader.Download(ctx, activation)
	if err != nil {
		return err
	}
	if err := r.Client.UploadProfileDownloadResult(ctx, r.EID, SuccessfulProfileDownloadResult(trigger.EimTransactionID)); err != nil {
		return err
	}
	logger.Info(
		"trigger->download->enable complete",
		"eid", hex.EncodeToString(r.EID),
		"profile", result.ProfileID,
		"smdp", result.SMDP,
		"liveSMDP", result.LiveSMDP,
		"offlineStub", result.Offline,
	)
	return nil
}

// IpaEuiccDataResponse builds representative eUICC/IPA data for the mock IPA.
func IpaEuiccDataResponse(eid []byte, request *protocolasn1.IpaEuiccDataRequest) (*protocolasn1.IpaEuiccDataResponse, error) {
	state := protocolasn1.ProfileStateEnabled
	profiles, err := (&protocolasn1.ProfileInfoListResponse{
		Profiles: []protocolasn1.ProfileInfo{{
			ICCID:             []byte{0x89, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55},
			ProfileState:      &state,
			FallbackAttribute: true,
		}},
	}).MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	transactionID := []byte(nil)
	if request != nil {
		transactionID = cloneBytes(request.EimTransactionID)
	}
	defaultSMDP := "smdp.example"
	rootSMDS := "smds.example"
	return &protocolasn1.IpaEuiccDataResponse{
		Data: &protocolasn1.IpaEuiccData{
			RawObjects: []*bertlv.TLV{
				bertlv.NewValue(bertlv.Application.Primitive(26), cloneBytes(eid)),
				bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte(defaultSMDP)),
				euiccInfo1TLV(),
				euiccInfo2TLV(),
				bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), []byte(rootSMDS)),
				ipaCapabilitiesTLV(),
				profiles,
				bertlv.NewValue(bertlv.ContextSpecific.Primitive(7), transactionID),
			},
		},
	}, nil
}

func euiccInfo1TLV() *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(32),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x03, 0x02, 0x01}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xaa, 0x01}),
		),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(10),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xbb, 0x02}),
		),
	)
}

func euiccInfo2TLV() *bertlv.TLV {
	category, _ := bertlv.MarshalValue(bertlv.ContextSpecific.Primitive(11), primitive.MarshalInt(int64(1)))
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(34),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte{0x03, 0x00, 0x00}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x03, 0x02, 0x01}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), []byte{0x01, 0x00, 0x00}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xaa, 0x01}),
		),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(10),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xcc, 0x03}),
		),
		category,
	)
}

func ipaCapabilitiesTLV() *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(8),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x02, 0xfc}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte{0x03, 0xc0}),
	)
}

// SuccessfulEUICCPackageResult builds the successful PSMO/ECO result emitted by
// the mock IPA. SeqNumber is left at zero; ESipa matches it to pending work by
// eIM ID, counter, and transaction ID.
func SuccessfulEUICCPackageResult(request *protocolasn1.EuiccPackageRequest) (*protocolasn1.EuiccPackageResult, string, error) {
	if request == nil {
		return nil, "", errors.New("mockipa: missing eUICC package request")
	}
	pkg := request.EuiccPackageSigned.EuiccPackage
	resultData, operation, err := successfulResultData(pkg, request.EuiccPackageSigned.EimID)
	if err != nil {
		return nil, "", err
	}
	return &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultOK,
		Signed: &protocolasn1.EuiccPackageResultSigned{
			Data: protocolasn1.EuiccPackageResultDataSigned{
				EimID:            request.EuiccPackageSigned.EimID,
				CounterValue:     request.EuiccPackageSigned.CounterValue,
				EimTransactionID: cloneBytes(request.EuiccPackageSigned.EimTransactionID),
				Results:          []protocolasn1.EuiccResultData{resultData},
			},
			EuiccSignEPR: []byte{0x30, 0x00},
		},
	}, operation, nil
}

func successfulResultData(pkg protocolasn1.EuiccPackage, eimID string) (protocolasn1.EuiccResultData, string, error) {
	switch pkg.Kind {
	case protocolasn1.EuiccPackagePSMO:
		if len(pkg.PSMOs) != 1 {
			return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: only single PSMO eUICC packages are supported")
		}
		return psmoResultData(pkg.PSMOs[0])
	case protocolasn1.EuiccPackageECO:
		if len(pkg.ECOs) != 1 {
			return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: only single ECO eUICC packages are supported")
		}
		return ecoResultData(pkg.ECOs[0], eimID)
	default:
		return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: unsupported eUICC package kind")
	}
}

func psmoResultData(psmo protocolasn1.Psmo) (protocolasn1.EuiccResultData, string, error) {
	switch psmo.Operation {
	case protocolasn1.PsmoEnable:
		resultData, err := protocolasn1.IntegerEuiccResult(3, 0)
		return resultData, "enable", err
	case protocolasn1.PsmoDisable:
		resultData, err := protocolasn1.IntegerEuiccResult(4, 0)
		return resultData, "disable", err
	case protocolasn1.PsmoDelete:
		resultData, err := protocolasn1.IntegerEuiccResult(5, 0)
		return resultData, "delete", err
	case protocolasn1.PsmoListProfileInfo:
		state := protocolasn1.ProfileStateDisabled
		resultData, err := protocolasn1.ProfileInfoListEuiccResult(&protocolasn1.ProfileInfoListResponse{
			Profiles: []protocolasn1.ProfileInfo{{
				ICCID:             []byte{0x89, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55},
				ProfileState:      &state,
				FallbackAttribute: true,
			}},
		})
		return resultData, "list-profile-info", err
	case protocolasn1.PsmoGetRAT:
		return protocolasn1.EuiccResultData{Raw: bertlv.NewChildren(bertlv.ContextSpecific.Constructed(6))}, "get-rat", nil
	case protocolasn1.PsmoConfigureImmediateEnable:
		resultData, err := protocolasn1.IntegerEuiccResult(7, 0)
		return resultData, "configure-immediate-enable", err
	case protocolasn1.PsmoSetFallbackAttribute:
		resultData, err := protocolasn1.IntegerEuiccResult(13, 0)
		return resultData, "set-fallback-attribute", err
	case protocolasn1.PsmoUnsetFallbackAttribute:
		resultData, err := protocolasn1.IntegerEuiccResult(14, 0)
		return resultData, "unset-fallback-attribute", err
	case protocolasn1.PsmoSetDefaultDPAddress:
		resultData, err := protocolasn1.SetDefaultDPAddressEuiccResult(&protocolasn1.SetDefaultDPAddressResponse{Result: 0})
		return resultData, "set-default-dp-address", err
	default:
		return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: unsupported PSMO operation")
	}
}

func ecoResultData(eco protocolasn1.Eco, eimID string) (protocolasn1.EuiccResultData, string, error) {
	switch eco.Operation {
	case protocolasn1.EcoAddEIM:
		token := int64(1)
		if eco.Config != nil && eco.Config.AssociationToken != nil {
			token = *eco.Config.AssociationToken
		}
		resultData, err := protocolasn1.AddEimEuiccResult(&protocolasn1.AddEimResult{AssociationToken: &token})
		return resultData, "add-eim", err
	case protocolasn1.EcoDeleteEIM:
		resultData, err := protocolasn1.IntegerEuiccResult(9, 2)
		return resultData, "delete-eim", err
	case protocolasn1.EcoUpdateEIM:
		resultData, err := protocolasn1.IntegerEuiccResult(10, 0)
		return resultData, "update-eim", err
	case protocolasn1.EcoListEIM:
		resultData, err := protocolasn1.ListEimEuiccResult(&protocolasn1.ListEimResult{
			EimIDList: []protocolasn1.EimIDInfo{{EimID: eimID}},
		})
		return resultData, "list-eim", err
	default:
		return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: unsupported ECO operation")
	}
}
