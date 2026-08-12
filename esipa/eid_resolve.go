package esipa

import (
	"bytes"
	"context"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
)

// ResolveProvideResultEID prefers an explicit Provide EID, then recovers from the
// result payload (BF52 EID / eUICC certificate), then from eimTransactionId
// against pending operation payloads when EID was omitted.
func ResolveProvideResultEID(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	explicitEID []byte,
	resultTLV *bertlv.TLV,
) (eid string, errCode *protocolasn1.EimPackageResultErrorCode, err error) {
	if len(explicitEID) != 0 {
		eid, code := eidKey(explicitEID)
		return eid, code, nil
	}
	if recovered := recoverEIDFromPackageResultTLV(resultTLV); len(recovered) == 16 {
		eid, code := eidKey(recovered)
		return eid, code, nil
	}
	transactionID := EimTransactionIDFromResultTLV(resultTLV)
	if len(transactionID) == 0 {
		code := getEimPackageErrorMissingEID
		return "", &code, nil
	}
	pending, err := store.ListPendingOperations(ctx, tenantID, 10000)
	if err != nil {
		return "", nil, err
	}
	for _, operation := range pending {
		matched, err := OperationMatchesEimTransactionID(operation, transactionID)
		if err != nil {
			return "", nil, err
		}
		if matched {
			return operation.EID, nil, nil
		}
	}
	code := provideResultErrorEIDNotFound
	return "", &code, nil
}

// EimTransactionIDFromResultTLV extracts eimTransactionId from a Provide result
// payload (BF51, BF52, BF54, or nested EimPackageResult arms).
func EimTransactionIDFromResultTLV(tlv *bertlv.TLV) []byte {
	if tlv == nil {
		return nil
	}
	if tlv.Tag.Equal(tagIpaEuiccData) {
		var response protocolasn1.IpaEuiccDataResponse
		if err := response.UnmarshalBERTLV(tlv); err != nil {
			return nil
		}
		if response.Error != nil {
			return cloneBytes(response.Error.EimTransactionID)
		}
		if response.Data != nil {
			return cloneBytes(response.Data.EimTransactionID)
		}
		return nil
	}
	if tlv.Tag.Equal(tagDownloadTrig) {
		var result protocolasn1.ProfileDownloadTriggerResult
		if err := result.UnmarshalBERTLV(tlv); err == nil {
			return cloneBytes(result.EimTransactionID)
		}
	}
	var result protocolasn1.EuiccPackageResult
	if err := result.UnmarshalBERTLV(tlv); err == nil {
		switch result.Kind {
		case protocolasn1.EuiccPackageResultOK:
			if result.Signed != nil {
				return cloneBytes(result.Signed.Data.EimTransactionID)
			}
		case protocolasn1.EuiccPackageResultErrorSigned:
			if result.ErrorSigned != nil {
				return cloneBytes(result.ErrorSigned.Data.EimTransactionID)
			}
		case protocolasn1.EuiccPackageResultErrorUnsigned:
			if result.ErrorUnsigned != nil {
				return cloneBytes(result.ErrorUnsigned.EimTransactionID)
			}
		}
	}
	var eimResult protocolasn1.EimPackageResult
	if err := eimResult.UnmarshalBERTLV(tlv); err == nil &&
		eimResult.ProfileDownloadResult != nil {
		return cloneBytes(eimResult.ProfileDownloadResult.EimTransactionID)
	}
	return firstContextPrimitive2(tlv)
}

// OperationMatchesEimTransactionID reports whether a pending operation payload
// carries the given eimTransactionId.
func OperationMatchesEimTransactionID(operation storage.Operation, transactionID []byte) (bool, error) {
	if len(transactionID) == 0 {
		return false, nil
	}
	switch operation.Kind {
	case storage.OperationEuiccPackage:
		var request protocolasn1.EuiccPackageRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return false, err
		}
		return bytes.Equal(request.EuiccPackageSigned.EimTransactionID, transactionID), nil
	case storage.OperationIpaEuiccData:
		var request protocolasn1.IpaEuiccDataRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return false, err
		}
		return bytes.Equal(request.EimTransactionID, transactionID), nil
	case storage.OperationProfileDownloadTrigger:
		var request protocolasn1.ProfileDownloadTriggerRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return false, err
		}
		return bytes.Equal(request.EimTransactionID, transactionID), nil
	default:
		return false, nil
	}
}

func firstContextPrimitive2(tlv *bertlv.TLV) []byte {
	if tlv == nil {
		return nil
	}
	if tlv.Tag.Equal(bertlv.ContextSpecific.Primitive(2)) {
		return cloneBytes(tlv.Value)
	}
	for _, child := range tlv.Children {
		if got := firstContextPrimitive2(child); got != nil {
			return got
		}
	}
	return nil
}
