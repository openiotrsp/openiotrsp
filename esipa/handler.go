// Package esipa implements the SGP.32 ESipa polling endpoint shared by the
// HTTPS and CoAP/DTLS transports.
package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	"github.com/openiotrsp/openiotrsp/profiledownload"
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
	errUnsupportedMessage = errors.New("esipa: unsupported IPA-to-eIM message")

	tagInteger          = bertlv.Universal.Primitive(2)
	tagSequence         = bertlv.Universal.Constructed(16)
	tagEID              = bertlv.Application.Primitive(26)
	tagEuiccPackage     = bertlv.ContextSpecific.Constructed(81)
	tagIpaEuiccData     = bertlv.ContextSpecific.Constructed(82)
	tagDownloadTrig     = bertlv.ContextSpecific.Constructed(84)
	tagTransferPackage  = bertlv.ContextSpecific.Constructed(78)
	tagGetEimPackage    = bertlv.ContextSpecific.Constructed(79)
	tagProvideResult    = bertlv.ContextSpecific.Constructed(80)
	tagHandleNotify     = bertlv.ContextSpecific.Constructed(61)
	tagNotificationList = bertlv.ContextSpecific.Constructed(0)
)

// Request is the exact SGP.32 ESipa IPA-to-eIM top-level envelope.
type Request struct {
	Message protocolasn1.ESipaMessageFromIpaToEim
}

// Response is the exact SGP.32 ESipa eIM-to-IPA top-level envelope.
type Response struct {
	Message protocolasn1.ESipaMessageFromEimToIpa
}

// Handler owns the shared ESipa request handling configuration.
type Handler struct {
	Store          storage.Store
	TenantID       storage.TenantID
	Path           string
	MaxMessageSize int64

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
	return Request{Message: message}, nil
}

// EncodeResponse encodes a BER-TLV ESipa eIM-to-IPA envelope.
func EncodeResponse(response Response) ([]byte, error) {
	return protocolasn1.Encode(&response.Message)
}

// Handle applies one decoded ESipa request to the Store and returns the decoded
// response. HTTP and CoAP/DTLS transports call this same function.
func Handle(ctx context.Context, store storage.Store, tenantID storage.TenantID, request Request) (Response, error) {
	if store == nil {
		return Response{}, errors.New("esipa: nil Store")
	}
	if request.Message.Raw == nil {
		return Response{}, errors.New("esipa: missing request message")
	}
	tenantID = storage.NormalizeTenantID(tenantID)

	switch {
	case request.Message.Raw.Tag.Equal(tagGetEimPackage):
		return handleGetEimPackage(ctx, store, tenantID, request.Message.Raw)
	case request.Message.Raw.Tag.Equal(tagProvideResult):
		return handleProvideEimPackageResult(ctx, store, tenantID, request.Message.Raw)
	case request.Message.Raw.Tag.Equal(tagTransferPackage):
		return handleTransferEimPackageResponse(ctx, store, tenantID, request.Message.Raw)
	case request.Message.Raw.Tag.Equal(tagHandleNotify):
		return handleNotification(ctx, store, tenantID, request.Message.Raw)
	default:
		return Response{}, fmt.Errorf("%w: %s", errUnsupportedMessage, request.Message.Raw.Tag.String())
	}
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
	if request.NotifyStateChange {
		if err := storeNotification(ctx, store, tenantID, eid, "state-change", tlv); err != nil {
			return Response{}, err
		}
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

func handleProvideEimPackageResult(ctx context.Context, store storage.Store, tenantID storage.TenantID, tlv *bertlv.TLV) (Response, error) {
	var request protocolasn1.ProvideEimPackageResult
	if err := request.UnmarshalBERTLV(tlv); err != nil {
		return Response{}, err
	}
	eid, code := eidKey(request.EID)
	if code != nil {
		return provideResultErrorResponse(*code)
	}
	ack, err := recordEimPackageResult(ctx, store, tenantID, eid, request.EimPackageResult.Raw)
	if errors.Is(err, storage.ErrNotFound) {
		return provideResultErrorResponse(provideResultErrorEIDNotFound)
	}
	if err != nil {
		return Response{}, err
	}
	return provideResultAckResponse(ack)
}

func handleTransferEimPackageResponse(ctx context.Context, store storage.Store, tenantID storage.TenantID, tlv *bertlv.TLV) (Response, error) {
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
	ack, err := recordEimPackageResult(ctx, store, tenantID, eid, request.Raw)
	if err != nil {
		return Response{}, err
	}
	return transferAckResponse(ack)
}

func handleNotification(ctx context.Context, store storage.Store, tenantID storage.TenantID, tlv *bertlv.TLV) (Response, error) {
	if len(tlv.Children) == 1 && tlv.Children[0].Tag.Equal(tagProvideResult) {
		return handleProvideEimPackageResult(ctx, store, tenantID, tlv.Children[0])
	}
	if err := storeNotification(ctx, store, tenantID, "", "handle-notification", tlv); err != nil {
		return Response{}, err
	}
	return getEimPackageErrorResponse(getEimPackageErrorNoPackage)
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
	resultTLV := tlv
	if tlv.Tag.Equal(tagSequence) {
		resultTLV = tlv.First(tagEuiccPackage)
		if resultTLV == nil {
			return nil, errors.New("esipa: EPRAndNotifications missing EuiccPackageResult")
		}
		if notification := tlv.First(tagNotificationList); notification != nil {
			if err := storeNotification(ctx, store, tenantID, eid, "epr-notification-list", notification); err != nil {
				return nil, err
			}
		}
	}

	var result protocolasn1.EuiccPackageResult
	if err := result.UnmarshalBERTLV(resultTLV); err != nil {
		return nil, err
	}
	operations, err := matchingEUICCPackageOperations(ctx, store, tenantID, eid, &result)
	if err != nil {
		return nil, err
	}
	sequenceNumbers := make([]protocolasn1.SequenceNumber, 0, len(operations))
	for _, operation := range operations {
		status, err := resultStatusForOperation(operation, &result)
		if err != nil {
			return nil, err
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
			if err := applyEUICCPackageOperationState(ctx, store, tenantID, operation, &result); err != nil {
				return nil, err
			}
		}
		sequenceNumbers = append(sequenceNumbers, protocolasn1.SequenceNumber(operation.SequenceNumber))
	}
	return &protocolasn1.EimAcknowledgements{SequenceNumbers: sequenceNumbers}, nil
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
	ackTLV, err := ack.MarshalBERTLV()
	if err != nil {
		return Response{}, err
	}
	return responseFromMarshaler(&protocolasn1.ProvideEimPackageResultResponse{Raw: ackTLV})
}

func provideResultErrorResponse(code protocolasn1.EimPackageResultErrorCode) (Response, error) {
	tlv, err := integerTLV(code)
	if err != nil {
		return Response{}, err
	}
	return responseFromMarshaler(&protocolasn1.ProvideEimPackageResultResponse{Raw: tlv})
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

func storeNotification(ctx context.Context, store storage.Store, tenantID storage.TenantID, eid string, kind string, tlv *bertlv.TLV) error {
	if eid == "" {
		return nil
	}
	payload, err := tlv.MarshalBinary()
	if err != nil {
		return err
	}
	return store.StoreNotification(ctx, tenantID, storage.Notification{
		EID:     eid,
		Kind:    kind,
		Payload: payload,
	})
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

func integerTLV(value protocolasn1.EimPackageResultErrorCode) (*bertlv.TLV, error) {
	return bertlv.MarshalValue(tagInteger, primitive.MarshalInt(value))
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
