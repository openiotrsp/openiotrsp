package euiccpkg

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/damonto/euicc-go/bertlv"
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
	Logger *slog.Logger
}

// SignInput contains the tenant/device data needed to create a signed package.
type SignInput struct {
	TenantID         storage.TenantID
	EID              string
	EIDValue         []byte
	EimTransactionID []byte
	AssociationToken *int64
	Package          protocolasn1.EuiccPackage
}

// SignedRequest is a constructed EuiccPackageRequest plus the metadata needed
// to match and apply its result.
type SignedRequest struct {
	Request          protocolasn1.EuiccPackageRequest
	DER              []byte
	SignedDER        []byte
	SignatureInput   []byte
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
	token := input.AssociationToken
	if token == nil {
		token, err = s.associationToken(ctx, input.TenantID, input.EID)
		if err != nil {
			return nil, err
		}
	}
	signatureInput, err := signatureInput(signedDER, token)
	if err != nil {
		return nil, err
	}
	logPackageSigned(s.Logger, s.EimID, input, counter, token, signatureInput)

	signature, err := s.Signer.Sign(ctx, signatureInput)
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
		SignatureInput:   signatureInput,
		TenantID:         input.TenantID,
		EID:              input.EID,
		EIDValue:         cloneBytes(input.EIDValue),
		EimID:            s.EimID,
		CounterValue:     counter,
		EimTransactionID: cloneBytes(input.EimTransactionID),
		Package:          input.Package,
	}, nil
}

func logPackageSigned(logger *slog.Logger, eimID string, input SignInput, counter int64, associationToken *int64, signatureInput []byte) {
	if logger == nil {
		return
	}
	attrs := []any{
		"eid", input.EID,
		"eim_id", eimID,
		"counter", counter,
		"operation", PackageOperationKind(input.Package).String(),
		"signature_input_len", len(signatureInput),
		"association_token_configured", associationToken != nil,
	}
	if len(input.EimTransactionID) > 0 {
		attrs = append(attrs, "transaction_id_hex", hex.EncodeToString(input.EimTransactionID))
	}
	if associationToken != nil {
		attrs = append(attrs, "association_token_value", *associationToken)
	}
	logger.Info("euicc package signed", attrs...)
}

func (s *Service) associationToken(ctx context.Context, tenantID storage.TenantID, eid string) (*int64, error) {
	associated, err := s.Store.GetAssociatedEIM(ctx, tenantID, eid, s.EimID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var config protocolasn1.EimConfigurationData
	if err := protocolasn1.Decode(associated.ConfigPayload, &config); err != nil {
		return nil, fmt.Errorf("decode stored Associated eIM config: %w", err)
	}
	if config.AssociationToken == nil {
		return nil, nil
	}
	value := *config.AssociationToken
	return &value, nil
}

func signatureInput(signedDER []byte, associationToken *int64) ([]byte, error) {
	value := int64(0)
	if associationToken != nil {
		value = *associationToken
	}
	tokenDER, err := associationTokenTLV(value)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(signedDER)+len(tokenDER))
	out = append(out, signedDER...)
	out = append(out, tokenDER...)
	return out, nil
}

func associationTokenTLV(value int64) ([]byte, error) {
	tlv, err := bertlv.MarshalValue(bertlv.ContextSpecific.Primitive(4), primitive.MarshalInt(value))
	if err != nil {
		return nil, err
	}
	return tlv.MarshalBinary()
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
	OK                      bool
	Operation               OperationKind
	ResultCode              ResultCode
	ECOResultCode           ECOResultCode
	RawResultCode           int64
	AddEIMAssociationToken  *int64
	LastEIMDeleted          bool
	EIMs                    []EIMInfo
	Profiles                []ProfileInfo
	RulesAuthorisationTable *protocolasn1.TLV
	PackageError            PackageError
	RawPackageError         int64
	UnsignedPackageError    UnsignedPackageError
	RawUnsignedError        int64
}

// EIMInfo is the domain form of SGP.32 EimIdInfo in listEimResult.
type EIMInfo struct {
	EIMID     string
	EIMIDType *protocolasn1.EimIDType
}

// ProfileInfo is the domain form of the persisted subset of SGP.32 ProfileInfo.
type ProfileInfo struct {
	ICCID      string
	IsEnabled  bool
	IsFallback bool
}

// ParseOperationResult maps raw EuiccResultData to the domain result for one
// single-operation package without verifying the eUICC signature.
func ParseOperationResult(pkg protocolasn1.EuiccPackage, results []protocolasn1.EuiccResultData) (*Result, error) {
	return operationResult(&SignedRequest{Package: pkg}, results)
}

// VerifyPackageResult decodes an eUICC Package Result, verifies any eUICC
// signature against the supplied public key, and maps it to the domain result.
// It does not record or apply state.
func VerifyPackageResult(input ResultInput) (*Result, error) {
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
	return verifyResult(&decoded, input, rawSignedData)
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

	result, err := VerifyPackageResult(input)
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
		if err := ApplyPackageResultState(ctx, s.Store, input.Request.TenantID, input.Request.EID, input.Request.Package, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func verifyResult(decoded *protocolasn1.EuiccPackageResult, input ResultInput, rawSignedData []byte) (*Result, error) {
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
	if operation != OperationNone {
		return psmoOperationResult(operation, results)
	}
	operation, _ = requestECO(request)
	if operation != OperationNone {
		return ecoOperationResult(operation, results)
	}
	return &Result{OK: true, Operation: OperationNone, ResultCode: ResultOK}, nil
}

func psmoOperationResult(operation OperationKind, results []protocolasn1.EuiccResultData) (*Result, error) {
	wantTag := operation.resultTag()
	for index := range results {
		raw := results[index].Raw
		if raw == nil || !raw.Tag.ContextSpecific() || raw.Tag.Value() != wantTag {
			continue
		}
		switch operation {
		case OperationListProfileInfo:
			return listProfileInfoResult(raw)
		case OperationGetRAT:
			return &Result{
				OK:                      true,
				Operation:               operation,
				ResultCode:              ResultOK,
				RulesAuthorisationTable: raw.Clone(),
			}, nil
		case OperationSetDefaultDPAddress:
			return setDefaultDPAddressResult(raw)
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

func listProfileInfoResult(raw *protocolasn1.TLV) (*Result, error) {
	var decoded protocolasn1.ProfileInfoListResponse
	if err := decoded.UnmarshalBERTLV(raw); err != nil {
		return nil, err
	}
	result := &Result{Operation: OperationListProfileInfo}
	if decoded.Error != nil {
		value := int64(*decoded.Error)
		result.ResultCode = mapOperationResult(OperationListProfileInfo, value)
		result.RawResultCode = value
		return result, nil
	}
	result.OK = true
	result.ResultCode = ResultOK
	result.Profiles = make([]ProfileInfo, 0, len(decoded.Profiles))
	for _, profile := range decoded.Profiles {
		if len(profile.ICCID) == 0 {
			continue
		}
		isEnabled := false
		if profile.ProfileState != nil {
			isEnabled = *profile.ProfileState == protocolasn1.ProfileStateEnabled
		}
		result.Profiles = append(result.Profiles, ProfileInfo{
			ICCID:      fmt.Sprintf("%x", profile.ICCID),
			IsEnabled:  isEnabled,
			IsFallback: profile.FallbackAttribute,
		})
	}
	return result, nil
}

func setDefaultDPAddressResult(raw *protocolasn1.TLV) (*Result, error) {
	var decoded protocolasn1.SetDefaultDPAddressResponse
	if err := decoded.UnmarshalBERTLV(raw); err != nil {
		return nil, err
	}
	value := decoded.Result
	code := mapOperationResult(OperationSetDefaultDPAddress, value)
	return &Result{
		OK:            code == ResultOK,
		Operation:     OperationSetDefaultDPAddress,
		ResultCode:    code,
		RawResultCode: value,
	}, nil
}

func ecoOperationResult(operation OperationKind, results []protocolasn1.EuiccResultData) (*Result, error) {
	raw := resultDataByTag(results, operation.resultTag())
	if raw == nil {
		return nil, fmt.Errorf("euiccpkg: result for operation %s not found", operation)
	}
	switch operation {
	case OperationAddEIM:
		return addEIMResult(raw)
	case OperationDeleteEIM:
		value, err := integerResult(raw)
		if err != nil {
			return nil, err
		}
		code := mapDeleteEIMResult(value)
		return &Result{
			OK:             code == ECOResultOK || code == ECOResultLastEIMDeleted,
			Operation:      operation,
			ECOResultCode:  code,
			RawResultCode:  value,
			LastEIMDeleted: code == ECOResultLastEIMDeleted,
		}, nil
	case OperationUpdateEIM:
		value, err := integerResult(raw)
		if err != nil {
			return nil, err
		}
		code := mapUpdateEIMResult(value)
		return &Result{
			OK:            code == ECOResultOK,
			Operation:     operation,
			ECOResultCode: code,
			RawResultCode: value,
		}, nil
	case OperationListEIM:
		return listEIMResult(raw)
	default:
		return nil, fmt.Errorf("euiccpkg: unsupported ECO operation %s", operation)
	}
}

func resultDataByTag(results []protocolasn1.EuiccResultData, wantTag uint64) *protocolasn1.TLV {
	for index := range results {
		raw := results[index].Raw
		if raw != nil && raw.Tag.ContextSpecific() && raw.Tag.Value() == wantTag {
			return raw
		}
	}
	return nil
}

func addEIMResult(raw *protocolasn1.TLV) (*Result, error) {
	child, err := explicitResultChild(raw, 8)
	if err != nil {
		return nil, err
	}
	var decoded protocolasn1.AddEimResult
	if err := decoded.UnmarshalBERTLV(child); err != nil {
		return nil, err
	}
	result := &Result{Operation: OperationAddEIM}
	if decoded.AssociationToken != nil {
		token := *decoded.AssociationToken
		result.OK = true
		result.ECOResultCode = ECOResultOK
		result.AddEIMAssociationToken = &token
		return result, nil
	}
	if decoded.Code == nil {
		return nil, errors.New("euiccpkg: addEimResult has no selected value")
	}
	value := int64(*decoded.Code)
	code := mapAddEIMResult(value)
	result.OK = code == ECOResultOK
	result.ECOResultCode = code
	result.RawResultCode = value
	return result, nil
}

func listEIMResult(raw *protocolasn1.TLV) (*Result, error) {
	child, err := explicitResultChild(raw, 11)
	if err != nil {
		return nil, err
	}
	var decoded protocolasn1.ListEimResult
	if err := decoded.UnmarshalBERTLV(child); err != nil {
		return nil, err
	}
	result := &Result{Operation: OperationListEIM}
	if decoded.Error != nil {
		value := int64(*decoded.Error)
		result.ECOResultCode = mapListEIMResult(value)
		result.RawResultCode = value
		return result, nil
	}
	result.OK = true
	result.ECOResultCode = ECOResultOK
	result.EIMs = make([]EIMInfo, 0, len(decoded.EimIDList))
	for _, item := range decoded.EimIDList {
		var eimType *protocolasn1.EimIDType
		if item.EimIDType != nil {
			value := *item.EimIDType
			eimType = &value
		}
		result.EIMs = append(result.EIMs, EIMInfo{EIMID: item.EimID, EIMIDType: eimType})
	}
	return result, nil
}

func explicitResultChild(raw *protocolasn1.TLV, tag uint64) (*protocolasn1.TLV, error) {
	if raw == nil || !raw.Tag.ContextSpecific() || raw.Tag.Value() != tag {
		return nil, fmt.Errorf("euiccpkg: result tag got %v, want [%d]", raw, tag)
	}
	if len(raw.Children) != 1 {
		return nil, fmt.Errorf("euiccpkg: explicit ECO result [%d] must contain one child", tag)
	}
	return raw.Children[0], nil
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
	case OperationListProfileInfo:
		switch value {
		case 1:
			return ResultIncorrectInputValues
		case 11:
			return ResultProfileChangeOngoing
		case 127:
			return ResultUndefinedError
		}
	case OperationConfigureImmediateEnable:
		switch value {
		case 1:
			return ResultInsufficientMemory
		case 7:
			return ResultCommandError
		case 127:
			return ResultUndefinedError
		}
	case OperationSetFallbackAttribute:
		switch value {
		case 1:
			return ResultICCIDOrAIDNotFound
		case 2:
			return ResultFallbackNotAllowed
		case 3:
			return ResultFallbackProfileEnabled
		case 127:
			return ResultUndefinedError
		}
	case OperationUnsetFallbackAttribute:
		switch value {
		case 2:
			return ResultNoFallbackAttribute
		case 3:
			return ResultFallbackProfileEnabled
		case 7:
			return ResultCommandError
		case 127:
			return ResultUndefinedError
		}
	case OperationSetDefaultDPAddress:
		switch value {
		case 127:
			return ResultUndefinedError
		}
	}
	return ResultUnknown
}

func mapAddEIMResult(value int64) ECOResultCode {
	switch value {
	case 0:
		return ECOResultOK
	case 1:
		return ECOResultInsufficientMemory
	case 2:
		return ECOResultAssociatedEIMAlreadyExists
	case 3:
		return ECOResultCIPKUnknown
	case 5:
		return ECOResultInvalidAssociationToken
	case 6:
		return ECOResultCounterValueOutOfRange
	case 7:
		return ECOResultCommandError
	case 127:
		return ECOResultUndefinedError
	default:
		return ECOResultUnknown
	}
}

func mapDeleteEIMResult(value int64) ECOResultCode {
	switch value {
	case 0:
		return ECOResultOK
	case 1:
		return ECOResultEIMNotFound
	case 2:
		return ECOResultLastEIMDeleted
	case 7:
		return ECOResultCommandError
	case 127:
		return ECOResultUndefinedError
	default:
		return ECOResultUnknown
	}
}

func mapUpdateEIMResult(value int64) ECOResultCode {
	switch value {
	case 0:
		return ECOResultOK
	case 1:
		return ECOResultEIMNotFound
	case 3:
		return ECOResultCIPKUnknown
	case 6:
		return ECOResultCounterValueOutOfRange
	case 7:
		return ECOResultCommandError
	case 127:
		return ECOResultUndefinedError
	default:
		return ECOResultUnknown
	}
}

func mapListEIMResult(value int64) ECOResultCode {
	switch value {
	case 127:
		return ECOResultUndefinedError
	default:
		return ECOResultUnknown
	}
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
