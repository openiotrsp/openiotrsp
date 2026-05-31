package asn1

import (
	"errors"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
)

// ESipaMessageFromIpaToEim is the top-level SGP.32 ESipa CHOICE from IPA to eIM.
type ESipaMessageFromIpaToEim struct {
	Raw *bertlv.TLV
}

// MarshalBERTLV encodes ESipaMessageFromIpaToEim.
func (m *ESipaMessageFromIpaToEim) MarshalBERTLV() (*bertlv.TLV, error) {
	if m == nil || m.Raw == nil {
		return nil, errors.New("asn1: missing ESipa IPA-to-eIM message")
	}
	return cloneTLV(m.Raw), nil
}

// UnmarshalBERTLV decodes ESipaMessageFromIpaToEim.
func (m *ESipaMessageFromIpaToEim) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if !isAllowedTag(tlv, 57, 59, 58, 65, 61, 78, 79, 80) {
		return fmt.Errorf("%w: invalid IPA-to-eIM ESipa tag", errUnexpectedTag)
	}
	m.Raw = cloneTLV(tlv)
	return nil
}

// ESipaMessageFromEimToIpa is the top-level SGP.32 ESipa CHOICE from eIM to IPA.
type ESipaMessageFromEimToIpa struct {
	Raw *bertlv.TLV
}

// MarshalBERTLV encodes ESipaMessageFromEimToIpa.
func (m *ESipaMessageFromEimToIpa) MarshalBERTLV() (*bertlv.TLV, error) {
	if m == nil || m.Raw == nil {
		return nil, errors.New("asn1: missing ESipa eIM-to-IPA message")
	}
	return cloneTLV(m.Raw), nil
}

// UnmarshalBERTLV decodes ESipaMessageFromEimToIpa.
func (m *ESipaMessageFromEimToIpa) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if !isAllowedTag(tlv, 57, 59, 58, 65, 78, 79, 80) {
		return fmt.Errorf("%w: invalid eIM-to-IPA ESipa tag", errUnexpectedTag)
	}
	m.Raw = cloneTLV(tlv)
	return nil
}

// TransferEimPackageRequestKind identifies the selected TransferEimPackageRequest.
type TransferEimPackageRequestKind int

const (
	// TransferEuiccPackageRequest selects euiccPackageRequest.
	TransferEuiccPackageRequest TransferEimPackageRequestKind = iota + 1
	// TransferIpaEuiccDataRequest selects ipaEuiccDataRequest.
	TransferIpaEuiccDataRequest
	// TransferEimAcknowledgements selects eimAcknowledgements.
	TransferEimAcknowledgements
	// TransferProfileDownloadTriggerRequest selects profileDownloadTriggerRequest.
	TransferProfileDownloadTriggerRequest
)

// TransferEimPackageRequest is SGP.32 TransferEimPackageRequest, tag BF4E.
type TransferEimPackageRequest struct {
	Kind                          TransferEimPackageRequestKind
	EuiccPackageRequest           *EuiccPackageRequest
	IpaEuiccDataRequest           *bertlv.TLV
	EimAcknowledgements           *EimAcknowledgements
	ProfileDownloadTriggerRequest *ProfileDownloadTriggerRequest
}

// MarshalBERTLV encodes TransferEimPackageRequest.
func (r *TransferEimPackageRequest) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil TransferEimPackageRequest")
	}
	child, err := r.transferChild()
	if err != nil {
		return nil, err
	}
	return constructed(tagTransferEimPackage, child), nil
}

// UnmarshalBERTLV decodes TransferEimPackageRequest.
func (r *TransferEimPackageRequest) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagTransferEimPackage); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: TransferEimPackageRequest requires one selected child")
	}
	child := tlv.Children[0]
	var out TransferEimPackageRequest
	switch {
	case hasTag(child, tagEuiccPkg):
		out.Kind = TransferEuiccPackageRequest
		out.EuiccPackageRequest = new(EuiccPackageRequest)
		if err := out.EuiccPackageRequest.UnmarshalBERTLV(child); err != nil {
			return err
		}
	case hasTag(child, tagIpaEuiccData):
		out.Kind = TransferIpaEuiccDataRequest
		out.IpaEuiccDataRequest = cloneTLV(child)
	case hasTag(child, tagEimAck):
		out.Kind = TransferEimAcknowledgements
		out.EimAcknowledgements = new(EimAcknowledgements)
		if err := out.EimAcknowledgements.UnmarshalBERTLV(child); err != nil {
			return err
		}
	case hasTag(child, tagDownloadTrig):
		out.Kind = TransferProfileDownloadTriggerRequest
		out.ProfileDownloadTriggerRequest = new(ProfileDownloadTriggerRequest)
		if err := out.ProfileDownloadTriggerRequest.UnmarshalBERTLV(child); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown TransferEimPackageRequest child %s", errUnexpectedTag, child.Tag.String())
	}
	*r = out
	return nil
}

func (r *TransferEimPackageRequest) transferChild() (*bertlv.TLV, error) {
	switch r.Kind {
	case TransferEuiccPackageRequest:
		if r.EuiccPackageRequest == nil {
			return nil, errors.New("asn1: missing EuiccPackageRequest")
		}
		return r.EuiccPackageRequest.MarshalBERTLV()
	case TransferIpaEuiccDataRequest:
		if r.IpaEuiccDataRequest == nil {
			return nil, errors.New("asn1: missing IpaEuiccDataRequest")
		}
		return cloneTLV(r.IpaEuiccDataRequest), nil
	case TransferEimAcknowledgements:
		if r.EimAcknowledgements == nil {
			return nil, errors.New("asn1: missing EimAcknowledgements")
		}
		return r.EimAcknowledgements.MarshalBERTLV()
	case TransferProfileDownloadTriggerRequest:
		if r.ProfileDownloadTriggerRequest == nil {
			return nil, errors.New("asn1: missing ProfileDownloadTriggerRequest")
		}
		return r.ProfileDownloadTriggerRequest.MarshalBERTLV()
	default:
		return nil, fmt.Errorf("asn1: unknown TransferEimPackageRequest kind %d", r.Kind)
	}
}

// TransferEimPackageResponse is SGP.32 TransferEimPackageResponse, tag BF4E.
type TransferEimPackageResponse struct {
	Raw *bertlv.TLV
}

// MarshalBERTLV encodes TransferEimPackageResponse.
func (r *TransferEimPackageResponse) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil || r.Raw == nil {
		return nil, errors.New("asn1: missing TransferEimPackageResponse child")
	}
	return constructed(tagTransferEimPackage, cloneTLV(r.Raw)), nil
}

// UnmarshalBERTLV decodes TransferEimPackageResponse.
func (r *TransferEimPackageResponse) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagTransferEimPackage); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: TransferEimPackageResponse requires one selected child")
	}
	r.Raw = cloneTLV(tlv.Children[0])
	return nil
}

// StateChangeCause is SGP.32 StateChangeCause.
type StateChangeCause int64

// GetEimPackageRequest is SGP.32 GetEimPackageRequest, tag BF4F.
type GetEimPackageRequest struct {
	EID               []byte
	NotifyStateChange bool
	StateChangeCause  *StateChangeCause
	RPLMN             []byte
}

// MarshalBERTLV encodes GetEimPackageRequest.
func (r *GetEimPackageRequest) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil GetEimPackageRequest")
	}
	children := []*bertlv.TLV{octetTLV(tagEID, r.EID)}
	if r.NotifyStateChange {
		children = append(children, nullTLV(bertlv.ContextSpecific.Primitive(0)))
	}
	if r.StateChangeCause != nil {
		child, err := integerTLV(bertlv.ContextSpecific.Primitive(1), *r.StateChangeCause)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if r.RPLMN != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(2), r.RPLMN))
	}
	return constructed(tagGetEimPackage, children...), nil
}

// UnmarshalBERTLV decodes GetEimPackageRequest.
func (r *GetEimPackageRequest) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagGetEimPackage); err != nil {
		return err
	}
	var out GetEimPackageRequest
	var err error
	if out.EID, err = octetValue(tlv.First(tagEID)); err != nil {
		return err
	}
	out.NotifyStateChange = tlv.First(bertlv.ContextSpecific.Primitive(0)) != nil
	if child := tlv.First(bertlv.ContextSpecific.Primitive(1)); child != nil {
		value, err := integerValue[StateChangeCause](child)
		if err != nil {
			return err
		}
		out.StateChangeCause = &value
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		out.RPLMN = copyBytes(child.Value)
	}
	*r = out
	return nil
}

// GetEimPackageResponseKind identifies the selected GetEimPackageResponse.
type GetEimPackageResponseKind int

const (
	// GetEimPackageEuiccPackageRequest selects euiccPackageRequest.
	GetEimPackageEuiccPackageRequest GetEimPackageResponseKind = iota + 1
	// GetEimPackageIpaEuiccDataRequest selects ipaEuiccDataRequest.
	GetEimPackageIpaEuiccDataRequest
	// GetEimPackageProfileDownloadTriggerRequest selects profileDownloadTriggerRequest.
	GetEimPackageProfileDownloadTriggerRequest
	// GetEimPackageError selects eimPackageError.
	GetEimPackageError
)

// GetEimPackageResponse is SGP.32 GetEimPackageResponse, tag BF4F.
type GetEimPackageResponse struct {
	Kind                          GetEimPackageResponseKind
	EuiccPackageRequest           *EuiccPackageRequest
	IpaEuiccDataRequest           *bertlv.TLV
	ProfileDownloadTriggerRequest *ProfileDownloadTriggerRequest
	Error                         *EimPackageResultErrorCode
}

// MarshalBERTLV encodes GetEimPackageResponse.
func (r *GetEimPackageResponse) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil GetEimPackageResponse")
	}
	child, err := r.getResponseChild()
	if err != nil {
		return nil, err
	}
	return constructed(tagGetEimPackage, child), nil
}

// UnmarshalBERTLV decodes GetEimPackageResponse.
func (r *GetEimPackageResponse) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagGetEimPackage); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: GetEimPackageResponse requires one selected child")
	}
	child := tlv.Children[0]
	var out GetEimPackageResponse
	switch {
	case hasTag(child, tagEuiccPkg):
		out.Kind = GetEimPackageEuiccPackageRequest
		out.EuiccPackageRequest = new(EuiccPackageRequest)
		if err := out.EuiccPackageRequest.UnmarshalBERTLV(child); err != nil {
			return err
		}
	case hasTag(child, tagIpaEuiccData):
		out.Kind = GetEimPackageIpaEuiccDataRequest
		out.IpaEuiccDataRequest = cloneTLV(child)
	case hasTag(child, tagDownloadTrig):
		out.Kind = GetEimPackageProfileDownloadTriggerRequest
		out.ProfileDownloadTriggerRequest = new(ProfileDownloadTriggerRequest)
		if err := out.ProfileDownloadTriggerRequest.UnmarshalBERTLV(child); err != nil {
			return err
		}
	case hasTag(child, tagInteger):
		out.Kind = GetEimPackageError
		value, err := integerValue[EimPackageResultErrorCode](child)
		if err != nil {
			return err
		}
		out.Error = &value
	default:
		return fmt.Errorf("%w: unknown GetEimPackageResponse child %s", errUnexpectedTag, child.Tag.String())
	}
	*r = out
	return nil
}

func (r *GetEimPackageResponse) getResponseChild() (*bertlv.TLV, error) {
	switch r.Kind {
	case GetEimPackageEuiccPackageRequest:
		if r.EuiccPackageRequest == nil {
			return nil, errors.New("asn1: missing EuiccPackageRequest")
		}
		return r.EuiccPackageRequest.MarshalBERTLV()
	case GetEimPackageIpaEuiccDataRequest:
		if r.IpaEuiccDataRequest == nil {
			return nil, errors.New("asn1: missing IpaEuiccDataRequest")
		}
		return cloneTLV(r.IpaEuiccDataRequest), nil
	case GetEimPackageProfileDownloadTriggerRequest:
		if r.ProfileDownloadTriggerRequest == nil {
			return nil, errors.New("asn1: missing ProfileDownloadTriggerRequest")
		}
		return r.ProfileDownloadTriggerRequest.MarshalBERTLV()
	case GetEimPackageError:
		if r.Error == nil {
			return nil, errors.New("asn1: missing GetEimPackageResponse error")
		}
		return integerTLV(tagInteger, *r.Error)
	default:
		return nil, fmt.Errorf("asn1: unknown GetEimPackageResponse kind %d", r.Kind)
	}
}

// EimPackageResultErrorCode is SGP.32 EimPackageResultErrorCode.
type EimPackageResultErrorCode int64

// EimPackageResult is SGP.32 EimPackageResult.
type EimPackageResult struct {
	Raw *bertlv.TLV
}

// MarshalBERTLV encodes EimPackageResult.
func (r *EimPackageResult) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil || r.Raw == nil {
		return nil, errors.New("asn1: missing EimPackageResult")
	}
	return cloneTLV(r.Raw), nil
}

// UnmarshalBERTLV decodes EimPackageResult.
func (r *EimPackageResult) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing EimPackageResult")
	}
	if !isEimPackageResultTLV(tlv) {
		return fmt.Errorf("%w: unknown EimPackageResult tag %s", errUnexpectedTag, tlv.Tag.String())
	}
	r.Raw = cloneTLV(tlv)
	return nil
}

// ProvideEimPackageResult is SGP.32 ProvideEimPackageResult, tag BF50.
type ProvideEimPackageResult struct {
	EID              []byte
	EimPackageResult EimPackageResult
}

// MarshalBERTLV encodes ProvideEimPackageResult.
func (r *ProvideEimPackageResult) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil ProvideEimPackageResult")
	}
	result, err := r.EimPackageResult.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	var children []*bertlv.TLV
	if r.EID != nil {
		children = append(children, octetTLV(tagEID, r.EID))
	}
	children = append(children, result)
	return constructed(tagProvideEimResult, children...), nil
}

// UnmarshalBERTLV decodes ProvideEimPackageResult.
func (r *ProvideEimPackageResult) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagProvideEimResult); err != nil {
		return err
	}
	var out ProvideEimPackageResult
	if child := tlv.First(tagEID); child != nil {
		out.EID = copyBytes(child.Value)
	}
	for _, child := range tlv.Children {
		if !child.Tag.Equal(tagEID) {
			if err := out.EimPackageResult.UnmarshalBERTLV(child); err != nil {
				return err
			}
			*r = out
			return nil
		}
	}
	return errors.New("asn1: missing EimPackageResult")
}

// ProvideEimPackageResultResponse is SGP.32 ProvideEimPackageResultResponse, tag BF50.
type ProvideEimPackageResultResponse struct {
	Raw *bertlv.TLV
}

// MarshalBERTLV encodes ProvideEimPackageResultResponse.
func (r *ProvideEimPackageResultResponse) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil || r.Raw == nil {
		return nil, errors.New("asn1: missing ProvideEimPackageResultResponse child")
	}
	return constructed(tagProvideEimResult, cloneTLV(r.Raw)), nil
}

// UnmarshalBERTLV decodes ProvideEimPackageResultResponse.
func (r *ProvideEimPackageResultResponse) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagProvideEimResult); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: ProvideEimPackageResultResponse requires one selected child")
	}
	r.Raw = cloneTLV(tlv.Children[0])
	return nil
}

func isAllowedTag(tlv *bertlv.TLV, numbers ...uint64) bool {
	if tlv == nil || !tlv.Tag.ContextSpecific() || !tlv.Tag.Constructed() {
		return false
	}
	for _, number := range numbers {
		if tlv.Tag.Value() == number {
			return true
		}
	}
	return false
}

func isEimPackageResultTLV(tlv *bertlv.TLV) bool {
	if tlv == nil {
		return false
	}
	if tlv.Tag.Equal(tagEuiccPkg) || tlv.Tag.Equal(tagIpaEuiccData) || tlv.Tag.Equal(tagDownloadTrig) {
		return true
	}
	if tlv.Tag.Equal(bertlv.ContextSpecific.Constructed(0)) {
		return true
	}
	if tlv.Tag.Equal(tagSequence) {
		return len(tlv.Children) > 0 && hasTag(tlv.Children[0], tagEuiccPkg)
	}
	return false
}
