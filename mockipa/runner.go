package mockipa

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/profiledownload"
)

// Runner polls ESipa, executes supported instructions, and uploads results.
type Runner struct {
	Client       Client
	Downloader   Downloader
	Fixture      *SGP26Fixture
	StateStore   *StateStore
	EID          []byte
	Device       *DeviceState
	PollInterval time.Duration
	Once         bool
	Logger       *slog.Logger

	NextNotificationSequence int64

	pendingNotifications          []pendingNotification
	device                        *DeviceState
	indirectProfileDownload       bool
	chainPresentationRequired     bool
	chainPresented                bool
	deferSignedPackageWarned      bool
	untrustedCIWarned             bool
}

type pendingNotification struct {
	SequenceNumber int64
	TLV            *bertlv.TLV
}

// Run starts the mock IPA polling loop.
func (r Runner) Run(ctx context.Context) error {
	if len(r.EID) == 0 {
		return errors.New("mockipa: missing EID")
	}
	if r.Fixture == nil {
		return errors.New("mockipa: SGP.26 fixture is required")
	}
	downloader := r.Downloader
	if downloader == nil {
		downloader = SysmocomDownloader{FixtureZip: "", IMEI: "490154203237518"}
	}
	interval := r.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if r.device == nil {
		if r.Device != nil {
			r.device = r.Device
		} else {
			r.device = newDeviceState()
		}
	}
	if r.StateStore != nil {
		if err := r.StateStore.Apply(r.device, &r.NextNotificationSequence, &r.indirectProfileDownload, &r.chainPresentationRequired, &r.chainPresented); err != nil {
			return err
		}
	}

	for {
		if err := r.pollOnce(ctx, downloader, logger); err != nil {
			return err
		}
		if err := r.persistState(); err != nil {
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

func (r *Runner) pollOnce(ctx context.Context, downloader Downloader, logger *slog.Logger) error {
	poll, err := r.Client.Poll(ctx, r.EID)
	if err != nil {
		return err
	}
	switch poll.Kind {
	case protocolasn1.GetEimPackageEuiccPackageRequest:
		logger.Info("eIM package received", "eid", hex.EncodeToString(r.EID), "kind", "euicc-package")
		return r.handleEUICCPackage(ctx, logger, poll.EuiccPackageRequest)
	case protocolasn1.GetEimPackageIpaEuiccDataRequest:
		logger.Info("eIM package received", "eid", hex.EncodeToString(r.EID), "kind", "ipa-euicc-data")
		return r.handleIpaEuiccDataRequest(ctx, logger, poll.IpaEuiccDataRequest)
	case protocolasn1.GetEimPackageProfileDownloadTriggerRequest:
		logger.Info("eIM package received", "eid", hex.EncodeToString(r.EID), "kind", "profile-download-trigger")
		return r.handleProfileDownloadTrigger(ctx, downloader, logger, poll.ProfileDownloadTriggerRequest)
	case protocolasn1.GetEimPackageError:
		logger.Info("no eIM package available", "eid", hex.EncodeToString(r.EID))
		return nil
	default:
		logger.Info("unsupported eIM package for mock IPA", "kind", poll.Kind)
		return nil
	}
}

func (r *Runner) handleIpaEuiccDataRequest(
	ctx context.Context,
	logger *slog.Logger,
	tlv *bertlv.TLV,
) error {
	var request protocolasn1.IpaEuiccDataRequest
	if err := request.UnmarshalBERTLV(tlv); err != nil {
		return err
	}
	response, err := buildIpaEuiccDataResponse(r.EID, r.Fixture, r.device, &request)
	if err != nil {
		return err
	}
	if err := r.Client.UploadIpaEuiccDataResponse(ctx, r.EID, response); err != nil {
		return err
	}
	r.chainPresented = true
	r.deferSignedPackageWarned = false
	certInfo := "none"
	if r.Fixture != nil {
		certInfo = fmt.Sprintf("eum=%dB euicc=%dB", len(r.Fixture.EUMCertificate), len(r.Fixture.EUICCCertificate))
	}
	logger.Info(
		"IPA eUICC data read complete",
		"eid", hex.EncodeToString(r.EID),
		"tagList", hex.EncodeToString(request.TagList),
		"certs", certInfo,
	)
	return nil
}

func (r *Runner) shouldDeferSignedPackage(logger *slog.Logger) bool {
	if !r.chainPresentationRequired || r.chainPresented {
		return false
	}
	r.warnAwaitingChainPresentation(logger)
	return true
}

func (r *Runner) handleEUICCPackage(
	ctx context.Context,
	logger *slog.Logger,
	request *protocolasn1.EuiccPackageRequest,
) error {
	if r.shouldDeferSignedPackage(logger) {
		return nil
	}
	result, operation, err := r.buildPackageResult(request)
	if err != nil {
		return err
	}
	if notificationKind := notificationKindForOperation(operation); notificationKind != "" {
		if _, err := r.queueNotification(notificationKind); err != nil {
			return err
		}
		ack, err := r.Client.UploadEUICCPackageResultWithNotifications(ctx, r.EID, result, r.pendingNotificationTLVs())
		if err != nil {
			if IsRetriableESipaError(err) {
				r.handleRetriableESipaError(logger, operation, err)
				return nil
			}
			return err
		}
		r.applyOperationState(request, operation)
		r.acknowledgeNotifications(ack)
		logger.Info("eUICC package notification acknowledged", "eid", hex.EncodeToString(r.EID), "operation", operation, "acknowledged", ack.SequenceNumbers)
	} else {
		if err := r.Client.UploadEUICCPackageResult(ctx, r.EID, result); err != nil {
			if IsRetriableESipaError(err) {
				r.handleRetriableESipaError(logger, operation, err)
				return nil
			}
			return err
		}
		r.applyOperationState(request, operation)
	}
	logger.Info("eUICC package operation complete", "eid", hex.EncodeToString(r.EID), "operation", operation)
	return nil
}

func (r *Runner) handleRetriableESipaError(logger *slog.Logger, operation string, err error) {
	if IsChainNotPresentedError(err) {
		r.chainPresentationRequired = true
		r.chainPresented = false
		r.dropPendingNotifications()
		r.warnAwaitingChainPresentation(logger)
	} else if IsUntrustedCIError(err) {
		r.warnUntrustedCI(logger)
	}
	logger.Warn(
		"eIM rejected signed eUICC package",
		"eid", hex.EncodeToString(r.EID),
		"operation", operation,
		"error", err,
	)
}

func (r *Runner) warnUntrustedCI(logger *slog.Logger) {
	if r.untrustedCIWarned {
		return
	}
	r.untrustedCIWarned = true
	ciPath := "testdata/sgp26_variant_o/CERT_CI_SIG_NIST.der"
	logger.Error(
		"eIM does not trust the SGP.26 Variant O test CI root; add CERT_CI_SIG_NIST.der from the GSMA SGP.26 fixture to the eIM trusted CI store",
		"eid", hex.EncodeToString(r.EID),
		"ciCert", ciPath,
	)
}

func (r *Runner) warnAwaitingChainPresentation(logger *slog.Logger) {
	if r.deferSignedPackageWarned {
		return
	}
	r.deferSignedPackageWarned = true
	logger.Warn(
		"deferring signed eUICC packages: cancel pending euicc-package operations on the eIM, queue only POST /v1/devices/{eid}/euicc-data/fetch, then re-queue PSMO after IPA eUICC data completes",
		"eid", hex.EncodeToString(r.EID),
	)
}

func (r *Runner) dropPendingNotifications() {
	r.pendingNotifications = nil
}

func (r *Runner) handleProfileDownloadTrigger(
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
	activeDownloader := downloader
	if r.indirectProfileDownload {
		activeDownloader = IndirectDownloader{
			Client:     r.Client,
			FixtureZip: "",
			IMEI:       indirectDownloaderIMEI(downloader),
		}
	}
	logger.Info("profile download trigger received", "smdp", activation.SMDPAddress, "matchingID", activation.MatchingID, "indirect", r.indirectProfileDownload)
	result, err := activeDownloader.Download(ctx, activation)
	if err != nil {
		return err
	}
	if err := r.Client.UploadProfileDownloadResult(ctx, r.EID, ProfileDownloadResult(trigger.EimTransactionID, result.ProfileInstallationResult)); err != nil {
		return err
	}
	r.device.recordDownload(result.ProfileID, result.SMDP)
	notification, err := r.queueNotification("install")
	if err != nil {
		return err
	}
	if err := r.Client.SendNotification(ctx, notification.TLV); err != nil {
		return err
	}
	r.clearNotification(notification.SequenceNumber)
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

func (r *Runner) queueNotification(kind string) (pendingNotification, error) {
	sequenceNumber := r.nextNotificationSequence()
	signed, err := SignedNotification(r.Fixture, r.EID, sequenceNumber, kind)
	if err != nil {
		return pendingNotification{}, err
	}
	notification := pendingNotification{
		SequenceNumber: sequenceNumber,
		TLV:            signed,
	}
	r.pendingNotifications = append(r.pendingNotifications, notification)
	return notification, nil
}

func (r *Runner) pendingNotificationTLVs() []*bertlv.TLV {
	notifications := make([]*bertlv.TLV, 0, len(r.pendingNotifications))
	for _, notification := range r.pendingNotifications {
		if notification.TLV != nil {
			notifications = append(notifications, notification.TLV.Clone())
		}
	}
	return notifications
}

func (r *Runner) acknowledgeNotifications(ack *protocolasn1.EimAcknowledgements) {
	if ack == nil || len(ack.SequenceNumbers) == 0 {
		return
	}
	acknowledged := make(map[int64]bool, len(ack.SequenceNumbers))
	for _, sequenceNumber := range ack.SequenceNumbers {
		acknowledged[int64(sequenceNumber)] = true
	}
	pending := r.pendingNotifications[:0]
	for _, notification := range r.pendingNotifications {
		if !acknowledged[notification.SequenceNumber] {
			pending = append(pending, notification)
		}
	}
	r.pendingNotifications = pending
}

func (r *Runner) clearNotification(sequenceNumber int64) {
	r.acknowledgeNotifications(&protocolasn1.EimAcknowledgements{
		SequenceNumbers: []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(sequenceNumber)},
	})
}

func (r *Runner) nextNotificationSequence() int64 {
	if r.NextNotificationSequence <= 0 {
		r.NextNotificationSequence = 1
	}
	sequenceNumber := r.NextNotificationSequence
	r.NextNotificationSequence++
	return sequenceNumber
}

func (r *Runner) buildPackageResult(request *protocolasn1.EuiccPackageRequest) (*protocolasn1.EuiccPackageResult, string, error) {
	return SignedEUICCPackageResult(r.Fixture, r.device, request, 0)
}

func (r *Runner) persistState() error {
	if r.StateStore == nil {
		return nil
	}
	return r.StateStore.Save(r.device, r.NextNotificationSequence, r.indirectProfileDownload, r.chainPresentationRequired, r.chainPresented)
}

func (r *Runner) applyOperationState(request *protocolasn1.EuiccPackageRequest, operation string) {
	if r.device == nil || request == nil {
		return
	}
	pkg := request.EuiccPackageSigned.EuiccPackage
	if pkg.Kind != protocolasn1.EuiccPackagePSMO || len(pkg.PSMOs) != 1 {
		return
	}
	switch operation {
	case "enable":
		r.device.applyPSMO(pkg.PSMOs[0], true)
	case "disable":
		r.device.applyPSMO(pkg.PSMOs[0], false)
	case "delete":
		if len(pkg.PSMOs[0].ICCID) > 0 {
			delete(r.device.Profiles, hex.EncodeToString(pkg.PSMOs[0].ICCID))
		}
	case "set-fallback-attribute":
		r.device.setProfileFallback(pkg.PSMOs[0].ICCID)
	case "unset-fallback-attribute":
		r.device.clearProfileFallback()
	case "add-eim":
		if pkg.Kind == protocolasn1.EuiccPackageECO && len(pkg.ECOs) == 1 && pkg.ECOs[0].Config != nil {
			r.indirectProfileDownload = pkg.ECOs[0].Config.IndirectProfileDownload
		}
	case "update-eim":
		if pkg.Kind == protocolasn1.EuiccPackageECO && len(pkg.ECOs) == 1 && pkg.ECOs[0].Config != nil {
			r.indirectProfileDownload = pkg.ECOs[0].Config.IndirectProfileDownload
		}
	}
}

func indirectDownloaderIMEI(downloader Downloader) string {
	switch value := downloader.(type) {
	case SysmocomDownloader:
		return value.IMEI
	case IndirectDownloader:
		return value.IMEI
	default:
		return ""
	}
}

func notificationKindForOperation(operation string) string {
	switch operation {
	case "enable", "disable", "delete":
		return operation
	default:
		return ""
	}
}

func ipaCapabilitiesTLV() *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(8),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x02, 0xfc}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte{0x03, 0xc0}),
	)
}

func successfulResultData(pkg protocolasn1.EuiccPackage, eimID string, device *DeviceState) (protocolasn1.EuiccResultData, string, error) {
	switch pkg.Kind {
	case protocolasn1.EuiccPackagePSMO:
		if len(pkg.PSMOs) != 1 {
			return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: only single PSMO eUICC packages are supported")
		}
		return psmoResultData(pkg.PSMOs[0], device)
	case protocolasn1.EuiccPackageECO:
		if len(pkg.ECOs) != 1 {
			return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: only single ECO eUICC packages are supported")
		}
		return ecoResultData(pkg.ECOs[0], eimID)
	default:
		return protocolasn1.EuiccResultData{}, "", errors.New("mockipa: unsupported eUICC package kind")
	}
}

func psmoResultData(psmo protocolasn1.Psmo, device *DeviceState) (protocolasn1.EuiccResultData, string, error) {
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
		profiles := make([]protocolasn1.ProfileInfo, 0)
		if device != nil {
			for _, record := range device.Profiles {
				enabled := protocolasn1.ProfileStateEnabled
				disabled := protocolasn1.ProfileStateDisabled
				stateValue := &disabled
				if record.Enabled {
					stateValue = &enabled
				}
				profiles = append(profiles, protocolasn1.ProfileInfo{
					ICCID:             cloneBytes(record.ICCID),
					ProfileState:      stateValue,
					FallbackAttribute: record.Fallback,
				})
			}
		}
		resultData, err := protocolasn1.ProfileInfoListEuiccResult(&protocolasn1.ProfileInfoListResponse{Profiles: profiles})
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
