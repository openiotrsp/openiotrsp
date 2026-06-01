package euiccpkg

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/damonto/euicc-go/bertlv/primitive"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/signing"
	"github.com/openiotrsp/openiotrsp/storage"
)

// Service constructs signed packages and verifies package results.
type Service struct {
	Store  storage.Store
	Signer signing.Signer
	EimID  string
}

// SignInput contains the tenant/device data needed to create a signed package.
type SignInput struct {
	TenantID         storage.TenantID
	EID              string
	EIDValue         []byte
	EimTransactionID []byte
	Package          protocolasn1.EuiccPackage
}

// SignedRequest is a constructed EuiccPackageRequest plus the metadata needed
// to match and apply its result.
type SignedRequest struct {
	Request          protocolasn1.EuiccPackageRequest
	DER              []byte
	SignedDER        []byte
	TenantID         storage.TenantID
	EID              string
	EIDValue         []byte
	EimID            string
	CounterValue     int64
	EimTransactionID []byte
	Package          protocolasn1.EuiccPackage
}

// Sign creates EuiccPackageSigned with a strictly increasing per-eUICC counter,
// signs its DER encoding, and returns the encoded EuiccPackageRequest.
func (s *Service) Sign(ctx context.Context, input SignInput) (*SignedRequest, error) {
	if s == nil {
		return nil, errors.New("euiccpkg: nil Service")
	}
	if s.Store == nil {
		return nil, errors.New("euiccpkg: nil Store")
	}
	if s.Signer == nil {
		return nil, errors.New("euiccpkg: nil Signer")
	}
	if s.EimID == "" {
		return nil, errors.New("euiccpkg: missing eIM ID")
	}
	if input.EID == "" {
		return nil, errors.New("euiccpkg: missing EID")
	}

	counter, err := s.Store.NextEUICCPackageCounter(ctx, input.TenantID, input.EID)
	if err != nil {
		return nil, err
	}

	signed := protocolasn1.EuiccPackageSigned{
		EimID:            s.EimID,
		EID:              cloneBytes(input.EIDValue),
		CounterValue:     counter,
		EimTransactionID: cloneBytes(input.EimTransactionID),
		EuiccPackage:     input.Package,
	}
	signedDER, err := protocolasn1.Encode(&signed)
	if err != nil {
		return nil, fmt.Errorf("encode EuiccPackageSigned: %w", err)
	}
	signature, err := s.Signer.Sign(ctx, signedDER)
	if err != nil {
		return nil, err
	}

	request := protocolasn1.EuiccPackageRequest{
		EuiccPackageSigned: signed,
		EimSignature:       cloneBytes(signature),
	}
	der, err := protocolasn1.Encode(&request)
	if err != nil {
		return nil, fmt.Errorf("encode EuiccPackageRequest: %w", err)
	}

	return &SignedRequest{
		Request:          request,
		DER:              der,
		SignedDER:        signedDER,
		TenantID:         input.TenantID,
		EID:              input.EID,
		EIDValue:         cloneBytes(input.EIDValue),
		EimID:            s.EimID,
		CounterValue:     counter,
		EimTransactionID: cloneBytes(input.EimTransactionID),
		Package:          input.Package,
	}, nil
}

// ResultInput contains the expected request metadata and the DER eUICC result.
type ResultInput struct {
	Request        *SignedRequest
	ResultDER      []byte
	EUICCPublicKey crypto.PublicKey
	OperationID    int64
	SequenceNumber int64
}

// Result is the verified domain result.
type Result struct {
	OK                   bool
	Operation            OperationKind
	ResultCode           ResultCode
	RawResultCode        int64
	PackageError         PackageError
	RawPackageError      int64
	UnsignedPackageError UnsignedPackageError
	RawUnsignedError     int64
}

// VerifyAndApplyResult decodes an eUICC Package Result, verifies any eUICC
// signature, matches it to the signed request, records the operation result, and
// applies successful profile-state transitions.
func (s *Service) VerifyAndApplyResult(ctx context.Context, input ResultInput) (*Result, error) {
	if s == nil {
		return nil, errors.New("euiccpkg: nil Service")
	}
	if s.Store == nil {
		return nil, errors.New("euiccpkg: nil Store")
	}
	if input.Request == nil {
		return nil, errors.New("euiccpkg: missing signed request")
	}

	var decoded protocolasn1.EuiccPackageResult
	if err := protocolasn1.Decode(input.ResultDER, &decoded); err != nil {
		return nil, err
	}
	rawSignedData, err := rawSignedDataFromResultDER(input.ResultDER)
	if err != nil {
		return nil, err
	}

	result, err := s.verifyResult(&decoded, input, rawSignedData)
	if err != nil {
		return nil, err
	}

	status := storage.OperationDone
	if !result.OK {
		status = storage.OperationFailed
	}
	if input.OperationID != 0 || input.SequenceNumber != 0 {
		if err := s.Store.RecordEUICCPackageResult(ctx, input.Request.TenantID, storage.EUICCPackageResult{
			EID:            input.Request.EID,
			OperationID:    input.OperationID,
			SequenceNumber: input.SequenceNumber,
			Status:         status,
			Payload:        cloneBytes(input.ResultDER),
		}); err != nil {
			return nil, err
		}
	}

	if result.OK {
		operation, iccid := requestPSMO(input.Request)
		if err := applyPSMOState(ctx, s.Store, input.Request.TenantID, input.Request.EID, operation, iccid); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Service) verifyResult(decoded *protocolasn1.EuiccPackageResult, input ResultInput, rawSignedData []byte) (*Result, error) {
	switch decoded.Kind {
	case protocolasn1.EuiccPackageResultOK:
		if decoded.Signed == nil {
			return nil, errors.New("euiccpkg: missing signed result")
		}
		if err := verifySignedBytes(input.EUICCPublicKey, rawSignedData, decoded.Signed.EuiccSignEPR); err != nil {
			return nil, err
		}
		data := decoded.Signed.Data
		if err := matchSignedResult(input.Request, input.SequenceNumber, data.EimID, data.CounterValue, data.EimTransactionID, data.SeqNumber); err != nil {
			return nil, err
		}
		return operationResult(input.Request, data.Results)
	case protocolasn1.EuiccPackageResultErrorSigned:
		if decoded.ErrorSigned == nil {
			return nil, errors.New("euiccpkg: missing signed package error")
		}
		if err := verifySignedBytes(input.EUICCPublicKey, rawSignedData, decoded.ErrorSigned.EuiccSignEPE); err != nil {
			return nil, err
		}
		data := decoded.ErrorSigned.Data
		if err := matchSignedResult(input.Request, 0, data.EimID, data.CounterValue, data.EimTransactionID, 0); err != nil {
			return nil, err
		}
		code := int64(data.ErrorCode)
		return &Result{
			PackageError:    mapPackageError(code),
			RawPackageError: code,
		}, nil
	case protocolasn1.EuiccPackageResultErrorUnsigned:
		if decoded.ErrorUnsigned == nil {
			return nil, errors.New("euiccpkg: missing unsigned package error")
		}
		data := decoded.ErrorUnsigned
		if data.EimID != input.Request.EimID || !bytes.Equal(data.EimTransactionID, input.Request.EimTransactionID) {
			return nil, &VerificationError{Kind: ErrTransactionMismatch, Msg: "unsigned error does not match eIM ID or transaction ID"}
		}
		result := &Result{UnsignedPackageError: UnsignedPackageErrorMissing}
		if data.ErrorCode != nil {
			code := int64(*data.ErrorCode)
			result.UnsignedPackageError = mapUnsignedPackageError(code)
			result.RawUnsignedError = code
		}
		return result, nil
	default:
		return nil, fmt.Errorf("euiccpkg: unsupported result kind %d", decoded.Kind)
	}
}

func verifySignedBytes(publicKey crypto.PublicKey, signedData []byte, signature []byte) error {
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		if value, valueOK := publicKey.(ecdsa.PublicKey); valueOK {
			ecdsaKey = &value
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("euiccpkg: unsupported eUICC public key type %T", publicKey)
	}
	if len(signedData) == 0 {
		return errors.New("euiccpkg: missing raw signed data")
	}
	digest := sha256.Sum256(signedData)
	if !ecdsa.VerifyASN1(ecdsaKey, digest[:], signature) {
		return ErrSignatureInvalid
	}
	return nil
}

func matchSignedResult(request *SignedRequest, wantSequence int64, eimID string, counter int64, transactionID []byte, sequence int64) error {
	if eimID != request.EimID || !bytes.Equal(transactionID, request.EimTransactionID) {
		return &VerificationError{Kind: ErrTransactionMismatch, Msg: "signed result does not match eIM ID or transaction ID"}
	}
	if counter != request.CounterValue {
		return &VerificationError{
			Kind: ErrCounterMismatch,
			Msg:  fmt.Sprintf("got %d, want %d", counter, request.CounterValue),
		}
	}
	if wantSequence != 0 && sequence != wantSequence {
		return &VerificationError{
			Kind: ErrTransactionMismatch,
			Msg:  fmt.Sprintf("sequence got %d, want %d", sequence, wantSequence),
		}
	}
	return nil
}

func operationResult(request *SignedRequest, results []protocolasn1.EuiccResultData) (*Result, error) {
	operation, _ := requestPSMO(request)
	if operation == OperationNone {
		return &Result{OK: true, Operation: OperationNone, ResultCode: ResultOK}, nil
	}
	wantTag := operation.resultTag()
	for index := range results {
		raw := results[index].Raw
		if raw == nil || !raw.Tag.ContextSpecific() || raw.Tag.Value() != wantTag {
			continue
		}
		value, err := integerResult(raw)
		if err != nil {
			return nil, err
		}
		code := mapOperationResult(operation, value)
		return &Result{
			OK:            code == ResultOK,
			Operation:     operation,
			ResultCode:    code,
			RawResultCode: value,
		}, nil
	}
	return nil, fmt.Errorf("euiccpkg: result for operation %s not found", operation)
}

func integerResult(tlv *protocolasn1.TLV) (int64, error) {
	var value int64
	if err := tlv.UnmarshalValue(primitive.UnmarshalInt(&value)); err != nil {
		return 0, err
	}
	return value, nil
}

func mapOperationResult(operation OperationKind, value int64) ResultCode {
	if value == 0 {
		return ResultOK
	}
	switch operation {
	case OperationEnable:
		switch value {
		case 1:
			return ResultICCIDOrAIDNotFound
		case 2:
			return ResultProfileNotInDisabledState
		case 3:
			return ResultDisallowedByPolicy
		case 5:
			return ResultCatBusy
		case 20:
			return ResultRollbackNotAvailable
		case 127:
			return ResultUndefinedError
		}
	case OperationDisable:
		switch value {
		case 1:
			return ResultICCIDOrAIDNotFound
		case 2:
			return ResultProfileNotInEnabledState
		case 3:
			return ResultDisallowedByPolicy
		case 5:
			return ResultCatBusy
		case 127:
			return ResultUndefinedError
		}
	case OperationDelete:
		switch value {
		case 1:
			return ResultICCIDOrAIDNotFound
		case 2:
			return ResultProfileNotInDisabledState
		case 3:
			return ResultDisallowedByPolicy
		case 20:
			return ResultRollbackNotAvailable
		case 21:
			return ResultReturnFallbackProfile
		case 127:
			return ResultUndefinedError
		}
	}
	return ResultUnknown
}

func mapPackageError(value int64) PackageError {
	switch value {
	case 3:
		return PackageErrorInvalidEID
	case 4:
		return PackageErrorReplay
	case 6:
		return PackageErrorCounterValueOutOfRange
	case 15:
		return PackageErrorSizeOverflow
	case 104:
		return PackageErrorECallActive
	case 127:
		return PackageErrorUndefined
	default:
		return PackageErrorUnknown
	}
}

func mapUnsignedPackageError(value int64) UnsignedPackageError {
	switch value {
	case 15:
		return UnsignedPackageErrorSizeOverflow
	case 127:
		return UnsignedPackageErrorUndefined
	default:
		return UnsignedPackageErrorUnknown
	}
}
