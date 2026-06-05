// Package esipa implements the SGP.32 ESipa polling endpoint shared by the
// HTTPS and CoAP/DTLS transports.
package esipa

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	"github.com/openiotrsp/openiotrsp/ipadata"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
)

const (
	// DefaultPath is the transport path used by the HTTPS and CoAP handlers.
	DefaultPath = "/esipa"

	// MediaType is the HTTP content type used for BER-TLV encoded ESipa payloads.
	MediaType = "application/vnd.gsma.esipa.ber-tlv"

	// DefaultMaxMessageSize keeps handlers bounded while allowing block-wise eUICC
	// package transfers.
	DefaultMaxMessageSize = 1 << 20
)

const (
	getEimPackageErrorNoPackage   protocolasn1.EimPackageResultErrorCode = 1
	getEimPackageErrorEIDNotFound protocolasn1.EimPackageResultErrorCode = 2
	getEimPackageErrorInvalidEID  protocolasn1.EimPackageResultErrorCode = 3
	getEimPackageErrorMissingEID  protocolasn1.EimPackageResultErrorCode = 4

	provideResultErrorEIDNotFound protocolasn1.EimPackageResultErrorCode = 2
)

var (
	errUnsupportedMessage    = errors.New("esipa: unsupported IPA-to-eIM message")
	errMissingEUICCPublicKey = errors.New("esipa: eUICC public key resolver is required")

	tagSequence         = bertlv.Universal.Constructed(16)
	tagEID              = bertlv.Application.Primitive(26)
	tagEuiccPackage     = bertlv.ContextSpecific.Constructed(81)
	tagIpaEuiccData     = bertlv.ContextSpecific.Constructed(82)
	tagDownloadTrig     = bertlv.ContextSpecific.Constructed(84)
	tagInitiateAuth     = bertlv.ContextSpecific.Constructed(57)
	tagAuthenticate     = bertlv.ContextSpecific.Constructed(59)
	tagGetBoundPackage  = bertlv.ContextSpecific.Constructed(58)
	tagCancelSession    = bertlv.ContextSpecific.Constructed(65)
	tagTransferPackage  = bertlv.ContextSpecific.Constructed(78)
	tagGetEimPackage    = bertlv.ContextSpecific.Constructed(79)
	tagProvideResult    = bertlv.ContextSpecific.Constructed(80)
	tagHandleNotify     = bertlv.ContextSpecific.Constructed(61)
	tagNotificationList = bertlv.ContextSpecific.Constructed(0)
	tagNotificationMeta = bertlv.ContextSpecific.Constructed(47)
)

// Request is the exact SGP.32 ESipa IPA-to-eIM top-level envelope.
type Request struct {
	Message protocolasn1.ESipaMessageFromIpaToEim
	Raw     []byte
}

// Response is the exact SGP.32 ESipa eIM-to-IPA top-level envelope.
type Response struct {
	Message protocolasn1.ESipaMessageFromEimToIpa
	Raw     []byte
}

// EUICCPublicKeyResolver returns the trusted public key for verifying signed
// eUICC Package Results for one tenant-scoped eUICC.
type EUICCPublicKeyResolver func(ctx context.Context, tenantID storage.TenantID, eid string) (crypto.PublicKey, error)

// Handler owns the shared ESipa request handling configuration.
type Handler struct {
	Store          storage.Store
	TenantID       storage.TenantID
	Path           string
	MaxMessageSize int64
	EUICCPublicKey EUICCPublicKeyResolver
	// AllowUnverifiedEUICCPackageResults is a test/demo escape hatch for mock
	// eUICCs that cannot produce verifiable result signatures. Production
	// handlers must leave this false so state is not updated from unverified EPRs.
	AllowUnverifiedEUICCPackageResults bool
	Relay                              *relay.Relay

	blockwiseMu        sync.Mutex
	blockwiseResponses map[string]coapBlockwiseResponse
}

// NewHandler creates a Store-backed ESipa handler.
func NewHandler(store storage.Store, tenantID storage.TenantID) *Handler {
	return &Handler{
		Store:          store,
		TenantID:       storage.NormalizeTenantID(tenantID),
		Path:           DefaultPath,
		MaxMessageSize: DefaultMaxMessageSize,
	}
}

// DecodeRequest decodes a BER-TLV ESipa IPA-to-eIM envelope.
func DecodeRequest(data []byte) (Request, error) {
	var message protocolasn1.ESipaMessageFromIpaToEim
	if err := protocolasn1.Decode(data, &message); err != nil {
		return Request{}, err
	}
	return Request{Message: message, Raw: cloneBytes(data)}, nil
}

// EncodeResponse encodes a BER-TLV ESipa eIM-to-IPA envelope.
func EncodeResponse(response Response) ([]byte, error) {
	if response.Raw != nil {
		return cloneBytes(response.Raw), nil
	}
	return protocolasn1.Encode(&response.Message)
}

// Handle applies one decoded ESipa request to the Store and returns the decoded
// response. HTTP and CoAP/DTLS transports call this same function.
func Handle(ctx context.Context, store storage.Store, tenantID storage.TenantID, request Request) (Response, error) {
	return handle(ctx, store, tenantID, request, nil, false, nil)
}

func (h *Handler) handle(ctx context.Context, request Request) (Response, error) {
	if h == nil {
		return Response{}, errors.New("esipa: nil Handler")
	}
	return handle(ctx, h.Store, h.TenantID, request, h.EUICCPublicKey, h.AllowUnverifiedEUICCPackageResults, h.Relay)
}

func handle(ctx context.Context, store storage.Store, tenantID storage.TenantID, request Request, euiccPublicKey EUICCPublicKeyResolver, allowUnverifiedEUICCPackageResults bool, relayService *relay.Relay) (Response, error) {
	if request.Message.Raw == nil {
		return Response{}, errors.New("esipa: missing request message")
	}
	tenantID = storage.NormalizeTenantID(tenantID)

	switch {
	case shouldRelay(request.Message.Raw, relayService):
		return handleRelay(ctx, request, relayService)
	case request.Message.Raw.Tag.Equal(tagGetEimPackage):
		if store == nil {
			return Response{}, errors.New("esipa: nil Store")
		}
		return handleGetEimPackage(ctx, store, tenantID, request.Message.Raw)
	case request.Message.Raw.Tag.Equal(tagProvideResult):
		if store == nil {
			return Response{}, errors.New("esipa: nil Store")
		}
		return handleProvideEimPackageResult(ctx, store, tenantID, request.Message.Raw, euiccPublicKey, allowUnverifiedEUICCPackageResults)
	case request.Message.Raw.Tag.Equal(tagTransferPackage):
		if store == nil {
			return Response{}, errors.New("esipa: nil Store")
		}
		return handleTransferEimPackageResponse(ctx, store, tenantID, request.Message.Raw, euiccPublicKey, allowUnverifiedEUICCPackageResults)
	case request.Message.Raw.Tag.Equal(tagHandleNotify):
		if store == nil {
			return Response{}, errors.New("esipa: nil Store")
		}
		return handleNotification(ctx, store, tenantID, request.Message.Raw, euiccPublicKey, allowUnverifiedEUICCPackageResults)
	default:
		return Response{}, fmt.Errorf("%w: %s", errUnsupportedMessage, request.Message.Raw.Tag.String())
	}
}

func isRelayMessage(tlv *bertlv.TLV) bool {
	if tlv == nil {
		return false
	}
	return tlv.Tag.Equal(tagInitiateAuth) ||
		tlv.Tag.Equal(tagAuthenticate) ||
		tlv.Tag.Equal(tagGetBoundPackage) ||
		tlv.Tag.Equal(tagCancelSession) ||
		tlv.Tag.Equal(tagHandleNotify)
}

func shouldRelay(tlv *bertlv.TLV, relayService *relay.Relay) bool {
	if relayService == nil || !isRelayMessage(tlv) {
		return false
	}
	if !tlv.Tag.Equal(tagHandleNotify) {
		return true
	}
	if isLocalHandleNotification(tlv) {
		return false
	}
	payload, err := tlv.MarshalBinary()
	if err != nil {
		return false
	}
	return relayService.CanHandleNotification(payload)
}

func isLocalHandleNotification(tlv *bertlv.TLV) bool {
	if tlv == nil || !tlv.Tag.Equal(tagHandleNotify) || len(tlv.Children) != 1 {
		return false
	}
	child := tlv.Children[0]
	return child.Tag.Equal(tagNotificationList) || child.Tag.Equal(tagProvideResult)
}

func handleRelay(ctx context.Context, request Request, relayService *relay.Relay) (Response, error) {
	payload, err := relayRequestPayload(request)
	if err != nil {
		return Response{}, err
	}
	var relayed relay.Response
	switch {
	case request.Message.Raw.Tag.Equal(tagInitiateAuth):
		relayed, err = relayService.InitiateAuthentication(ctx, payload)
	case request.Message.Raw.Tag.Equal(tagAuthenticate):
		relayed, err = relayService.AuthenticateClient(ctx, payload)
	case request.Message.Raw.Tag.Equal(tagGetBoundPackage):
		relayed, err = relayService.GetBoundProfilePackage(ctx, payload)
	case request.Message.Raw.Tag.Equal(tagCancelSession):
		relayed, err = relayService.CancelSession(ctx, payload)
	case request.Message.Raw.Tag.Equal(tagHandleNotify):
		relayed, err = relayService.HandleNotification(ctx, payload)
	default:
		err = fmt.Errorf("%w: %s", errUnsupportedMessage, request.Message.Raw.Tag.String())
	}
	if err != nil {
		return Response{}, err
	}
	if request.Message.Raw.Tag.Equal(tagHandleNotify) || relayed.NoContent {
		return Response{}, nil
	}
	return relayResponse(relayed.Payload)
}

func relayRequestPayload(request Request) ([]byte, error) {
	if request.Raw != nil {
		return cloneBytes(request.Raw), nil
	}
	if request.Message.Raw == nil {
		return nil, errors.New("esipa: missing relay payload")
	}
	payload, err := request.Message.Raw.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func relayResponse(payload []byte) (Response, error) {
	if len(payload) == 0 {
		return Response{}, nil
	}
	var message protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(payload, &message); err != nil {
		return Response{}, err
	}
	return Response{
		Message: message,
		Raw:     cloneBytes(payload),
	}, nil
}

func handleGetEimPackage(ctx context.Context, store storage.Store, tenantID storage.TenantID, tlv *bertlv.TLV) (Response, error) {
	var request protocolasn1.GetEimPackageRequest
	if err := request.UnmarshalBERTLV(tlv); err != nil {
		return Response{}, err
	}
	eid, code := eidKey(request.EID)
	if code != nil {
		return getEimPackageErrorResponse(*code)
	}
	if err := ensureDeviceKnown(ctx, store, tenantID, eid); errors.Is(err, storage.ErrNotFound) {
		return getEimPackageErrorResponse(getEimPackageErrorEIDNotFound)
	} else if err != nil {
		return Response{}, err
	}
	operations, err := store.FetchPendingOperations(ctx, tenantID, eid, 1)
	if errors.Is(err, storage.ErrNotFound) {
		return getEimPackageErrorResponse(getEimPackageErrorEIDNotFound)
	}
	if err != nil {
		return Response{}, err
	}
	if len(operations) == 0 {
		return getEimPackageErrorResponse(getEimPackageErrorNoPackage)
	}

	response, err := getEimPackageOperationResponse(operations[0])
	if err != nil {
		return Response{}, err
	}
	return responseFromMarshaler(response)
}

func handleProvideEimPackageResult(ctx context.Context, store storage.Store, tenantID storage.TenantID, tlv *bertlv.TLV, euiccPublicKey EUICCPublicKeyResolver, allowUnverifiedEUICCPackageResults bool) (Response, error) {
	var request protocolasn1.ProvideEimPackageResult
	if err := request.UnmarshalBERTLV(tlv); err != nil {
		return Response{}, err
	}
	eid, code := eidKey(request.EID)
	if code != nil {
		return provideResultErrorResponse(*code)
	}
	ack, err := recordEimPackageResult(ctx, store, tenantID, eid, request.EimPackageResult.Raw, euiccPublicKey, allowUnverifiedEUICCPackageResults)
	if errors.Is(err, storage.ErrNotFound) {
		return provideResultErrorResponse(provideResultErrorEIDNotFound)
	}
	if err != nil {
		return Response{}, err
	}
	return provideResultAckResponse(ack)
}

func handleTransferEimPackageResponse(ctx context.Context, store storage.Store, tenantID storage.TenantID, tlv *bertlv.TLV, euiccPublicKey EUICCPublicKeyResolver, allowUnverifiedEUICCPackageResults bool) (Response, error) {
	var request protocolasn1.TransferEimPackageResponse
	if err := request.UnmarshalBERTLV(tlv); err != nil {
		return Response{}, err
	}
	// TransferEimPackageResponse has no EID field. The Store key cannot be
	// selected safely without a surrounding ProvideEimPackageResult.
	if request.Raw == nil || request.Raw.First(tagEID) == nil {
		return Response{}, errors.New("esipa: transfer result response does not identify an EID")
	}
	eid, code := eidKey(request.Raw.First(tagEID).Value)
	if code != nil {
		return transferAckResponse(nil)
	}
	ack, err := recordEimPackageResult(ctx, store, tenantID, eid, request.Raw, euiccPublicKey, allowUnverifiedEUICCPackageResults)
	if err != nil {
		return Response{}, err
	}
	return transferAckResponse(ack)
}

func handleNotification(ctx context.Context, store storage.Store, tenantID storage.TenantID, tlv *bertlv.TLV, euiccPublicKey EUICCPublicKeyResolver, allowUnverifiedEUICCPackageResults bool) (Response, error) {
	if len(tlv.Children) == 1 && tlv.Children[0].Tag.Equal(tagProvideResult) {
		_, err := handleProvideEimPackageResult(ctx, store, tenantID, tlv.Children[0], euiccPublicKey, allowUnverifiedEUICCPackageResults)
		return Response{}, err
	}
	notifications, err := notificationsFromHandleNotification(tlv)
	if err != nil {
		return Response{}, err
	}
	for _, notification := range notifications {
		if err := store.StoreNotification(ctx, tenantID, notification); err != nil {
			return Response{}, err
		}
	}
	return Response{}, nil
}

func recordNotificationsFromList(ctx context.Context, store storage.Store, tenantID storage.TenantID, eid string, tlv *bertlv.TLV) ([]protocolasn1.SequenceNumber, error) {
	if tlv == nil {
		return nil, nil
	}
	var notifications protocolasn1.PendingNotificationList
	if err := notifications.UnmarshalBERTLV(tlv); err != nil {
		return nil, err
	}
	sequenceNumbers := make([]protocolasn1.SequenceNumber, 0, len(notifications.Notifications))
	for index := range notifications.Notifications {
		notification, err := notificationFromPending(eid, &notifications.Notifications[index])
		if err != nil {
			return nil, err
		}
		if err := store.StoreNotification(ctx, tenantID, notification); err != nil {
			return nil, err
		}
		sequenceNumbers = append(sequenceNumbers, protocolasn1.SequenceNumber(notification.SequenceNumber))
	}
	return sequenceNumbers, nil
}

func notificationsFromHandleNotification(tlv *bertlv.TLV) ([]storage.Notification, error) {
	if tlv == nil {
		return nil, errors.New("esipa: missing HandleNotificationEsipa")
	}
	if len(tlv.Children) != 1 {
		return nil, errors.New("esipa: HandleNotificationEsipa requires one selected child")
	}
	child := tlv.Children[0]
	var notifications protocolasn1.PendingNotificationList
	if err := notifications.UnmarshalBERTLV(child); err == nil {
		out := make([]storage.Notification, 0, len(notifications.Notifications))
		for index := range notifications.Notifications {
			notification, err := notificationFromPending("", &notifications.Notifications[index])
			if err != nil {
				return nil, err
			}
			out = append(out, notification)
		}
		return out, nil
	}
	notification, err := notificationFromTLV("", child)
	if err != nil {
		return nil, err
	}
	return []storage.Notification{notification}, nil
}

func notificationFromTLV(eid string, tlv *bertlv.TLV) (storage.Notification, error) {
	var pending protocolasn1.PendingNotification
	if err := pending.UnmarshalBERTLV(tlv); err != nil {
		return storage.Notification{}, err
	}
	return notificationFromPending(eid, &pending)
}

func notificationFromPending(eid string, pending *protocolasn1.PendingNotification) (storage.Notification, error) {
	if pending == nil {
		return storage.Notification{}, errors.New("esipa: missing pending notification")
	}
	if eid == "" {
		if eidValue := pending.EID(); len(eidValue) == 16 {
			eid = hex.EncodeToString(eidValue)
		}
	}
	if eid == "" {
		return storage.Notification{}, errors.New("esipa: pending notification does not identify an EID")
	}
	sequenceNumber, err := pending.SequenceNumber()
	if err != nil {
		return storage.Notification{}, err
	}
	payloadTLV, err := pending.MarshalBERTLV()
	if err != nil {
		return storage.Notification{}, err
	}
	payload, err := payloadTLV.MarshalBinary()
	if err != nil {
		return storage.Notification{}, err
	}
	return storage.Notification{
		EID:            eid,
		SequenceNumber: sequenceNumber,
		Kind:           pending.Kind(),
		Payload:        payload,
	}, nil
}

func appendAckSequences(existing []protocolasn1.SequenceNumber, additions ...protocolasn1.SequenceNumber) []protocolasn1.SequenceNumber {
	for _, addition := range additions {
		seen := false
		for _, value := range existing {
			if value == addition {
				seen = true
				break
			}
		}
		if !seen {
			existing = append(existing, addition)
		}
	}
	return existing
}

func getEimPackageOperationResponse(operation storage.Operation) (*protocolasn1.GetEimPackageResponse, error) {
	switch operation.Kind {
	case storage.OperationEuiccPackage:
		var request protocolasn1.EuiccPackageRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return nil, err
		}
		return &protocolasn1.GetEimPackageResponse{
			Kind:                protocolasn1.GetEimPackageEuiccPackageRequest,
			EuiccPackageRequest: &request,
		}, nil
	case storage.OperationProfileDownloadTrigger:
		var request protocolasn1.ProfileDownloadTriggerRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return nil, err
		}
		return &protocolasn1.GetEimPackageResponse{
			Kind:                          protocolasn1.GetEimPackageProfileDownloadTriggerRequest,
			ProfileDownloadTriggerRequest: &request,
		}, nil
	case storage.OperationIpaEuiccData:
		tlv, err := parseOneTLV(operation.Payload)
		if err != nil {
			return nil, err
		}
		if !tlv.Tag.Equal(tagIpaEuiccData) {
			return nil, fmt.Errorf("esipa: IPA eUICC data operation has tag %s", tlv.Tag.String())
		}
		return &protocolasn1.GetEimPackageResponse{
			Kind:                protocolasn1.GetEimPackageIpaEuiccDataRequest,
			IpaEuiccDataRequest: tlv,
		}, nil
	default:
		return nil, fmt.Errorf("esipa: unsupported operation kind %q", operation.Kind)
	}
}

func recordEimPackageResult(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	tlv *bertlv.TLV,
	euiccPublicKey EUICCPublicKeyResolver,
	allowUnverifiedEUICCPackageResults bool,
) (*protocolasn1.EimAcknowledgements, error) {
	if tlv == nil {
		return nil, errors.New("esipa: missing EimPackageResult")
	}
	payload, err := tlv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if tlv.Tag.Equal(tagDownloadTrig) {
		return recordProfileDownloadTriggerResult(ctx, store, tenantID, eid, tlv, payload)
	}
	if tlv.Tag.Equal(tagIpaEuiccData) {
		return recordIpaEuiccDataResponse(ctx, store, tenantID, eid, tlv, payload)
	}
	resultTLV := tlv
	var notificationList *bertlv.TLV
	if tlv.Tag.Equal(tagSequence) {
		resultTLV = tlv.First(tagEuiccPackage)
		if resultTLV == nil {
			return nil, errors.New("esipa: EPRAndNotifications missing EuiccPackageResult")
		}
		notificationList = tlv.First(tagNotificationList)
	}

	var result protocolasn1.EuiccPackageResult
	if err := result.UnmarshalBERTLV(resultTLV); err != nil {
		return nil, err
	}
	resultDER, err := resultTLV.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var publicKey crypto.PublicKey
	if !allowUnverifiedEUICCPackageResults {
		if euiccPublicKey == nil {
			return nil, errMissingEUICCPublicKey
		}
		publicKey, err = euiccPublicKey(ctx, tenantID, eid)
		if err != nil {
			return nil, err
		}
		if publicKey == nil {
			return nil, errMissingEUICCPublicKey
		}
	}
	operations, err := matchingEUICCPackageOperations(ctx, store, tenantID, eid, &result)
	if err != nil {
		return nil, err
	}
	sequenceNumbers := make([]protocolasn1.SequenceNumber, 0, len(operations))
	for _, operation := range operations {
		var status storage.OperationStatus
		var domain *euiccpkg.Result
		if allowUnverifiedEUICCPackageResults {
			status, err = resultStatusForOperation(operation, &result)
			if err != nil {
				return nil, err
			}
		} else {
			domain, status, err = verifiedOperationResult(operation, tenantID, eid, resultDER, publicKey, &result)
			if err != nil {
				return nil, err
			}
		}
		if err := store.RecordEUICCPackageResult(ctx, tenantID, storage.EUICCPackageResult{
			EID:            eid,
			OperationID:    operation.ID,
			SequenceNumber: operation.SequenceNumber,
			Status:         status,
			Payload:        cloneBytes(payload),
		}); err != nil {
			return nil, err
		}
		if status == storage.OperationDone {
			if allowUnverifiedEUICCPackageResults {
				err = applyEUICCPackageOperationState(ctx, store, tenantID, operation, &result)
			} else {
				request, requestErr := signedRequestFromOperation(tenantID, eid, operation)
				if requestErr != nil {
					return nil, requestErr
				}
				err = euiccpkg.ApplyPackageResultState(ctx, store, tenantID, eid, request.Package, domain)
			}
			if err != nil {
				return nil, err
			}
		}
		sequenceNumbers = append(sequenceNumbers, protocolasn1.SequenceNumber(operation.SequenceNumber))
	}
	notificationSequences, err := recordNotificationsFromList(ctx, store, tenantID, eid, notificationList)
	if err != nil {
		return nil, err
	}
	sequenceNumbers = appendAckSequences(sequenceNumbers, notificationSequences...)
	return &protocolasn1.EimAcknowledgements{SequenceNumbers: sequenceNumbers}, nil
}

func recordIpaEuiccDataResponse(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	tlv *bertlv.TLV,
	payload []byte,
) (*protocolasn1.EimAcknowledgements, error) {
	var response protocolasn1.IpaEuiccDataResponse
	if err := response.UnmarshalBERTLV(tlv); err != nil {
		return nil, err
	}
	transactionID := ipaEuiccDataTransactionID(&response)
	operation, ok, err := pendingIpaEuiccDataOperation(ctx, store, tenantID, eid, transactionID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, storage.ErrNotFound
	}
	status := storage.OperationDone
	if response.Error != nil {
		status = storage.OperationFailed
	}
	if err := store.RecordEUICCPackageResult(ctx, tenantID, storage.EUICCPackageResult{
		EID:            eid,
		OperationID:    operation.ID,
		SequenceNumber: operation.SequenceNumber,
		Status:         status,
		Payload:        cloneBytes(payload),
	}); err != nil {
		return nil, err
	}
	if status == storage.OperationDone {
		if err := ipadata.ApplyResponse(ctx, store, tenantID, eid, &response, payload); err != nil {
			return nil, err
		}
	}
	sequenceNumbers := []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(operation.SequenceNumber)}
	if response.Data != nil {
		notificationSequences, err := recordNotificationsFromList(ctx, store, tenantID, eid, response.Data.NotificationsRaw)
		if err != nil {
			return nil, err
		}
		sequenceNumbers = appendAckSequences(sequenceNumbers, notificationSequences...)
	}
	return &protocolasn1.EimAcknowledgements{SequenceNumbers: sequenceNumbers}, nil
}

func pendingIpaEuiccDataOperation(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	transactionID []byte,
) (storage.Operation, bool, error) {
	operations, err := store.FetchPendingOperations(ctx, tenantID, eid, 100)
	if err != nil {
		return storage.Operation{}, false, err
	}
	for _, operation := range operations {
		if operation.Kind != storage.OperationIpaEuiccData {
			continue
		}
		if len(transactionID) == 0 {
			return operation, true, nil
		}
		var request protocolasn1.IpaEuiccDataRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return storage.Operation{}, false, err
		}
		if bytes.Equal(request.EimTransactionID, transactionID) {
			return operation, true, nil
		}
	}
	return storage.Operation{}, false, nil
}

func ipaEuiccDataTransactionID(response *protocolasn1.IpaEuiccDataResponse) []byte {
	if response == nil {
		return nil
	}
	if response.Error != nil {
		return response.Error.EimTransactionID
	}
	if response.Data != nil {
		return response.Data.EimTransactionID
	}
	return nil
}

func verifiedOperationResult(
	operation storage.Operation,
	tenantID storage.TenantID,
	eid string,
	resultDER []byte,
	publicKey crypto.PublicKey,
	result *protocolasn1.EuiccPackageResult,
) (*euiccpkg.Result, storage.OperationStatus, error) {
	request, err := signedRequestFromOperation(tenantID, eid, operation)
	if err != nil {
		return nil, storage.OperationFailed, err
	}
	sequenceNumber := int64(0)
	if result != nil && result.Kind == protocolasn1.EuiccPackageResultOK && result.Signed != nil && result.Signed.Data.SeqNumber != 0 {
		sequenceNumber = operation.SequenceNumber
	}
	domain, err := euiccpkg.VerifyPackageResult(euiccpkg.ResultInput{
		Request:        request,
		ResultDER:      resultDER,
		EUICCPublicKey: publicKey,
		SequenceNumber: sequenceNumber,
	})
	if err != nil {
		return nil, storage.OperationFailed, err
	}
	if !domain.OK {
		return domain, storage.OperationFailed, nil
	}
	return domain, storage.OperationDone, nil
}

func signedRequestFromOperation(tenantID storage.TenantID, eid string, operation storage.Operation) (*euiccpkg.SignedRequest, error) {
	if operation.Kind != storage.OperationEuiccPackage {
		return nil, fmt.Errorf("esipa: operation %d is %q, want eUICC package", operation.ID, operation.Kind)
	}
	var request protocolasn1.EuiccPackageRequest
	if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
		return nil, err
	}
	signed := request.EuiccPackageSigned
	return &euiccpkg.SignedRequest{
		Request:          request,
		DER:              cloneBytes(operation.Payload),
		TenantID:         tenantID,
		EID:              eid,
		EIDValue:         cloneBytes(signed.EID),
		EimID:            signed.EimID,
		CounterValue:     signed.CounterValue,
		EimTransactionID: cloneBytes(signed.EimTransactionID),
		Package:          signed.EuiccPackage,
	}, nil
}

func matchingEUICCPackageOperations(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	result *protocolasn1.EuiccPackageResult,
) ([]storage.Operation, error) {
	sequenceNumbers := resultSequenceNumbers(result)
	if len(sequenceNumbers) > 0 {
		operations := make([]storage.Operation, 0, len(sequenceNumbers))
		for _, sequence := range sequenceNumbers {
			operation, err := store.GetOperationBySequence(ctx, tenantID, eid, int64(sequence))
			if err != nil {
				return nil, err
			}
			operations = append(operations, operation)
		}
		return operations, nil
	}
	if result == nil || result.Kind != protocolasn1.EuiccPackageResultOK || result.Signed == nil {
		return nil, storage.ErrNotFound
	}
	pending, err := store.FetchPendingOperations(ctx, tenantID, eid, 10000)
	if err != nil {
		return nil, err
	}
	for _, operation := range pending {
		if operation.Kind != storage.OperationEuiccPackage {
			continue
		}
		var request protocolasn1.EuiccPackageRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return nil, err
		}
		signed := request.EuiccPackageSigned
		data := result.Signed.Data
		if signed.EimID == data.EimID &&
			signed.CounterValue == data.CounterValue &&
			bytes.Equal(signed.EimTransactionID, data.EimTransactionID) {
			return []storage.Operation{operation}, nil
		}
	}
	return nil, storage.ErrNotFound
}

func applyEUICCPackageOperationState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	operation storage.Operation,
	result *protocolasn1.EuiccPackageResult,
) error {
	if operation.Kind != storage.OperationEuiccPackage {
		return nil
	}
	var request protocolasn1.EuiccPackageRequest
	if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
		return err
	}
	var domain *euiccpkg.Result
	if result != nil && result.Kind == protocolasn1.EuiccPackageResultOK && result.Signed != nil {
		parsed, err := euiccpkg.ParseOperationResult(request.EuiccPackageSigned.EuiccPackage, result.Signed.Data.Results)
		if err != nil {
			return err
		}
		domain = parsed
	}
	return euiccpkg.ApplyPackageResultState(ctx, store, tenantID, operation.EID, request.EuiccPackageSigned.EuiccPackage, domain)
}

func recordProfileDownloadTriggerResult(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	tlv *bertlv.TLV,
	payload []byte,
) (*protocolasn1.EimAcknowledgements, error) {
	var result protocolasn1.ProfileDownloadTriggerResult
	if err := result.UnmarshalBERTLV(tlv); err != nil {
		return nil, err
	}
	operation, trigger, ok, err := pendingProfileDownloadTrigger(ctx, store, tenantID, eid, result.EimTransactionID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, storage.ErrNotFound
	}
	status := storage.OperationDone
	if result.Error != nil || result.ProfileInstallationSucceeded != nil && !*result.ProfileInstallationSucceeded {
		status = storage.OperationFailed
	}
	if err := store.RecordEUICCPackageResult(ctx, tenantID, storage.EUICCPackageResult{
		EID:            eid,
		OperationID:    operation.ID,
		SequenceNumber: operation.SequenceNumber,
		Status:         status,
		Payload:        cloneBytes(payload),
	}); err != nil {
		return nil, err
	}
	if status == storage.OperationDone {
		if err := recordDownloadedProfileState(ctx, store, tenantID, eid, &trigger); err != nil {
			return nil, err
		}
	}
	return &protocolasn1.EimAcknowledgements{
		SequenceNumbers: []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(operation.SequenceNumber)},
	}, nil
}

func pendingProfileDownloadTrigger(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	transactionID []byte,
) (storage.Operation, protocolasn1.ProfileDownloadTriggerRequest, bool, error) {
	operations, err := store.FetchPendingOperations(ctx, tenantID, eid, 100)
	if err != nil {
		return storage.Operation{}, protocolasn1.ProfileDownloadTriggerRequest{}, false, err
	}
	for _, operation := range operations {
		if operation.Kind != storage.OperationProfileDownloadTrigger {
			continue
		}
		var request protocolasn1.ProfileDownloadTriggerRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return storage.Operation{}, protocolasn1.ProfileDownloadTriggerRequest{}, false, err
		}
		if bytes.Equal(request.EimTransactionID, transactionID) {
			return operation, request, true, nil
		}
	}
	return storage.Operation{}, protocolasn1.ProfileDownloadTriggerRequest{}, false, nil
}

func recordDownloadedProfileState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	trigger *protocolasn1.ProfileDownloadTriggerRequest,
) error {
	if trigger == nil || trigger.ProfileDownloadData == nil || trigger.ProfileDownloadData.Kind != protocolasn1.ProfileDownloadActivationCode {
		return nil
	}
	activation, err := profiledownload.ParseActivationCode(trigger.ProfileDownloadData.ActivationCode)
	if err != nil {
		return nil
	}
	return store.SetProfileState(ctx, tenantID, storage.ProfileState{
		EID:         eid,
		ICCID:       activation.ProfileID(),
		IsEnabled:   true,
		SMDPAddress: activation.SMDPAddress,
	})
}

func resultSequenceNumbers(result *protocolasn1.EuiccPackageResult) []protocolasn1.SequenceNumber {
	if result == nil || result.Kind != protocolasn1.EuiccPackageResultOK || result.Signed == nil {
		return nil
	}
	if result.Signed.Data.SeqNumber == 0 {
		return nil
	}
	return []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(result.Signed.Data.SeqNumber)}
}

func resultStatus(result *protocolasn1.EuiccPackageResult) storage.OperationStatus {
	if result == nil || result.Kind != protocolasn1.EuiccPackageResultOK || result.Signed == nil {
		return storage.OperationFailed
	}
	for _, item := range result.Signed.Data.Results {
		if item.Raw == nil {
			continue
		}
		value, err := integerValue(item.Raw)
		if err == nil && value != 0 {
			return storage.OperationFailed
		}
	}
	return storage.OperationDone
}

func resultStatusForOperation(operation storage.Operation, result *protocolasn1.EuiccPackageResult) (storage.OperationStatus, error) {
	if operation.Kind != storage.OperationEuiccPackage || result == nil || result.Kind != protocolasn1.EuiccPackageResultOK || result.Signed == nil {
		return resultStatus(result), nil
	}
	var request protocolasn1.EuiccPackageRequest
	if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
		return storage.OperationFailed, err
	}
	parsed, err := euiccpkg.ParseOperationResult(request.EuiccPackageSigned.EuiccPackage, result.Signed.Data.Results)
	if err != nil {
		return storage.OperationFailed, err
	}
	if parsed.OK {
		return storage.OperationDone, nil
	}
	return storage.OperationFailed, nil
}

func getEimPackageErrorResponse(code protocolasn1.EimPackageResultErrorCode) (Response, error) {
	return responseFromMarshaler(&protocolasn1.GetEimPackageResponse{
		Kind:  protocolasn1.GetEimPackageError,
		Error: &code,
	})
}

func provideResultAckResponse(ack *protocolasn1.EimAcknowledgements) (Response, error) {
	if ack == nil {
		ack = &protocolasn1.EimAcknowledgements{}
	}
	return responseFromMarshaler(&protocolasn1.ProvideEimPackageResultResponse{
		Kind:             protocolasn1.ProvideResultResponseAcknowledgements,
		Acknowledgements: ack,
	})
}

func provideResultErrorResponse(code protocolasn1.EimPackageResultErrorCode) (Response, error) {
	return responseFromMarshaler(&protocolasn1.ProvideEimPackageResultResponse{
		Kind:  protocolasn1.ProvideResultResponseError,
		Error: &code,
	})
}

func transferAckResponse(ack *protocolasn1.EimAcknowledgements) (Response, error) {
	if ack == nil {
		ack = &protocolasn1.EimAcknowledgements{}
	}
	return responseFromMarshaler(&protocolasn1.TransferEimPackageRequest{
		Kind:                protocolasn1.TransferEimAcknowledgements,
		EimAcknowledgements: ack,
	})
}

func responseFromMarshaler(value protocolasn1.Marshaler) (Response, error) {
	tlv, err := value.MarshalBERTLV()
	if err != nil {
		return Response{}, err
	}
	return Response{Message: protocolasn1.ESipaMessageFromEimToIpa{Raw: tlv}}, nil
}

func eidKey(eid []byte) (string, *protocolasn1.EimPackageResultErrorCode) {
	switch len(eid) {
	case 0:
		code := getEimPackageErrorMissingEID
		return "", &code
	case 16:
		return hex.EncodeToString(eid), nil
	default:
		code := getEimPackageErrorInvalidEID
		return "", &code
	}
}

func ensureDeviceKnown(ctx context.Context, store storage.Store, tenantID storage.TenantID, eid string) error {
	_, err := store.ListProfileStates(ctx, tenantID, eid)
	return err
}

func parseOneTLV(data []byte) (*bertlv.TLV, error) {
	if len(data) == 0 {
		return nil, errors.New("esipa: empty BER-TLV input")
	}
	reader := bytes.NewReader(data)
	tlv := new(bertlv.TLV)
	n, err := tlv.ReadFrom(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("esipa: truncated BER-TLV input: %w", err)
		}
		return nil, err
	}
	if n != int64(len(data)) || reader.Len() != 0 {
		return nil, errors.New("esipa: trailing data after BER-TLV object")
	}
	return tlv, nil
}

func integerValue(tlv *bertlv.TLV) (int64, error) {
	var value int64
	if err := tlv.UnmarshalValue(primitive.UnmarshalInt(&value)); err != nil {
		return 0, err
	}
	return value, nil
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
