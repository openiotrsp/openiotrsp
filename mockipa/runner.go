package mockipa

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

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

// SuccessfulEUICCPackageResult builds the successful PSMO result emitted by the
// mock IPA. SeqNumber is left at zero; ESipa matches it to pending work by
// eIM ID, counter, and transaction ID.
func SuccessfulEUICCPackageResult(request *protocolasn1.EuiccPackageRequest) (*protocolasn1.EuiccPackageResult, string, error) {
	if request == nil {
		return nil, "", errors.New("mockipa: missing eUICC package request")
	}
	pkg := request.EuiccPackageSigned.EuiccPackage
	if pkg.Kind != protocolasn1.EuiccPackagePSMO || len(pkg.PSMOs) != 1 {
		return nil, "", errors.New("mockipa: only single PSMO eUICC packages are supported")
	}
	resultTag, operation, err := psmoResultTag(pkg.PSMOs[0].Operation)
	if err != nil {
		return nil, "", err
	}
	resultData, err := protocolasn1.IntegerEuiccResult(resultTag, 0)
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

func psmoResultTag(operation protocolasn1.PsmoOperation) (uint64, string, error) {
	switch operation {
	case protocolasn1.PsmoEnable:
		return 3, "enable", nil
	case protocolasn1.PsmoDisable:
		return 4, "disable", nil
	case protocolasn1.PsmoDelete:
		return 5, "delete", nil
	default:
		return 0, "", errors.New("mockipa: unsupported PSMO operation")
	}
}
