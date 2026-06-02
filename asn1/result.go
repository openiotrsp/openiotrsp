package asn1

import (
	"errors"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
)

// ProfileDownloadDataKind identifies the selected ProfileDownloadData CHOICE.
type ProfileDownloadDataKind int

const (
	// ProfileDownloadActivationCode selects activationCode.
	ProfileDownloadActivationCode ProfileDownloadDataKind = iota + 1
	// ProfileDownloadContactDefaultSMDP selects contactDefaultSmdp.
	ProfileDownloadContactDefaultSMDP
	// ProfileDownloadContactSMDS selects contactSmds.
	ProfileDownloadContactSMDS
)

// ProfileDownloadData is SGP.32 ProfileDownloadData.
type ProfileDownloadData struct {
	Kind           ProfileDownloadDataKind
	ActivationCode string
	SMDSAddress    *string
}

// MarshalBERTLV encodes ProfileDownloadData.
func (d *ProfileDownloadData) MarshalBERTLV() (*bertlv.TLV, error) {
	if d == nil {
		return nil, errors.New("asn1: nil ProfileDownloadData")
	}
	switch d.Kind {
	case ProfileDownloadActivationCode:
		return utf8TLV(bertlv.ContextSpecific.Primitive(0), d.ActivationCode), nil
	case ProfileDownloadContactDefaultSMDP:
		return nullTLV(bertlv.ContextSpecific.Primitive(1)), nil
	case ProfileDownloadContactSMDS:
		var children []*bertlv.TLV
		if d.SMDSAddress != nil {
			children = append(children, utf8TLV(tagUTF8, *d.SMDSAddress))
		}
		return constructed(bertlv.ContextSpecific.Constructed(2), children...), nil
	default:
		return nil, fmt.Errorf("asn1: unknown ProfileDownloadData kind %d", d.Kind)
	}
}

// UnmarshalBERTLV decodes ProfileDownloadData.
func (d *ProfileDownloadData) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing ProfileDownloadData")
	}
	var out ProfileDownloadData
	switch {
	case hasTag(tlv, bertlv.ContextSpecific.Primitive(0)):
		out.Kind = ProfileDownloadActivationCode
		value, err := utf8Value(tlv)
		if err != nil {
			return err
		}
		out.ActivationCode = value
	case hasTag(tlv, bertlv.ContextSpecific.Primitive(1)):
		out.Kind = ProfileDownloadContactDefaultSMDP
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(2)):
		out.Kind = ProfileDownloadContactSMDS
		if len(tlv.Children) > 0 {
			value, err := utf8Value(tlv.Children[0])
			if err != nil {
				return err
			}
			out.SMDSAddress = &value
		}
	default:
		return fmt.Errorf("%w: unknown ProfileDownloadData tag %s", errUnexpectedTag, tlv.Tag.String())
	}
	*d = out
	return nil
}

// ProfileDownloadTriggerRequest is SGP.32 ProfileDownloadTriggerRequest, tag BF54.
type ProfileDownloadTriggerRequest struct {
	ProfileDownloadData *ProfileDownloadData
	EimTransactionID    []byte
}

// MarshalBERTLV encodes ProfileDownloadTriggerRequest.
func (r *ProfileDownloadTriggerRequest) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil ProfileDownloadTriggerRequest")
	}
	var children []*bertlv.TLV
	if r.ProfileDownloadData != nil {
		data, err := r.ProfileDownloadData.MarshalBERTLV()
		if err != nil {
			return nil, err
		}
		children = append(children, constructed(bertlv.ContextSpecific.Constructed(0), data))
	}
	if r.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(2), r.EimTransactionID))
	}
	return constructed(tagDownloadTrig, children...), nil
}

// UnmarshalBERTLV decodes ProfileDownloadTriggerRequest.
func (r *ProfileDownloadTriggerRequest) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagDownloadTrig); err != nil {
		return err
	}
	var out ProfileDownloadTriggerRequest
	if wrapper := tlv.First(bertlv.ContextSpecific.Constructed(0)); wrapper != nil {
		if len(wrapper.Children) != 1 {
			return errors.New("asn1: profileDownloadData wrapper must contain one child")
		}
		data := new(ProfileDownloadData)
		if err := data.UnmarshalBERTLV(wrapper.Children[0]); err != nil {
			return err
		}
		out.ProfileDownloadData = data
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		out.EimTransactionID = copyBytes(child.Value)
	}
	*r = out
	return nil
}

// ProfileDownloadErrorReason identifies ProfileDownloadTriggerResult error reasons.
type ProfileDownloadErrorReason int64

const (
	// ProfileDownloadErrorECallActive indicates that an emergency profile is enabled.
	ProfileDownloadErrorECallActive ProfileDownloadErrorReason = 104
	// ProfileDownloadErrorUndefined is the generic profile download error.
	ProfileDownloadErrorUndefined ProfileDownloadErrorReason = 127
)

// ProfileDownloadError is the profileDownloadError branch of ProfileDownloadTriggerResult.
type ProfileDownloadError struct {
	Reason        ProfileDownloadErrorReason
	ErrorResponse []byte
}

// ProfileDownloadTriggerResult is SGP.32 ProfileDownloadTriggerResult, tag BF54.
type ProfileDownloadTriggerResult struct {
	EimTransactionID             []byte
	ProfileInstallationRaw       *bertlv.TLV
	ProfileInstallationSucceeded *bool
	Error                        *ProfileDownloadError
}

// MarshalBERTLV encodes ProfileDownloadTriggerResult.
func (r *ProfileDownloadTriggerResult) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil ProfileDownloadTriggerResult")
	}
	children := make([]*bertlv.TLV, 0, 2)
	if r.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(2), r.EimTransactionID))
	}
	switch {
	case r.ProfileInstallationRaw != nil:
		if !r.ProfileInstallationRaw.Tag.Equal(tagProfileInstall) {
			return nil, fmt.Errorf("%w: got %s, want %s", errUnexpectedTag, r.ProfileInstallationRaw.Tag.String(), tagProfileInstall.String())
		}
		children = append(children, cloneTLV(r.ProfileInstallationRaw))
	case r.Error != nil:
		errorTLV, err := r.Error.MarshalBERTLV()
		if err != nil {
			return nil, err
		}
		children = append(children, errorTLV)
	default:
		return nil, errors.New("asn1: ProfileDownloadTriggerResult requires result data")
	}
	return constructed(tagDownloadTrig, children...), nil
}

// UnmarshalBERTLV decodes ProfileDownloadTriggerResult.
func (r *ProfileDownloadTriggerResult) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagDownloadTrig); err != nil {
		return err
	}
	var out ProfileDownloadTriggerResult
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		out.EimTransactionID = copyBytes(child.Value)
	}
	switch child := profileDownloadResultData(tlv); {
	case child == nil:
		return errors.New("asn1: missing ProfileDownloadTriggerResult data")
	case child.Tag.Equal(tagProfileInstall):
		out.ProfileInstallationRaw = cloneTLV(child)
		succeeded, err := profileInstallationSucceeded(child)
		if err != nil {
			return err
		}
		out.ProfileInstallationSucceeded = &succeeded
	case child.Tag.Equal(tagSequence):
		out.Error = new(ProfileDownloadError)
		if err := out.Error.UnmarshalBERTLV(child); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown ProfileDownloadTriggerResult data tag %s", errUnexpectedTag, child.Tag.String())
	}
	*r = out
	return nil
}

// MarshalBERTLV encodes ProfileDownloadError.
func (e *ProfileDownloadError) MarshalBERTLV() (*bertlv.TLV, error) {
	if e == nil {
		return nil, errors.New("asn1: nil ProfileDownloadError")
	}
	reason, err := integerTLV(bertlv.ContextSpecific.Primitive(0), e.Reason)
	if err != nil {
		return nil, err
	}
	children := []*bertlv.TLV{reason}
	if e.ErrorResponse != nil {
		children = append(children, octetTLV(tagOctet, e.ErrorResponse))
	}
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes ProfileDownloadError.
func (e *ProfileDownloadError) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	var out ProfileDownloadError
	reason, err := integerValue[ProfileDownloadErrorReason](tlv.First(bertlv.ContextSpecific.Primitive(0)))
	if err != nil {
		return err
	}
	out.Reason = reason
	if child := tlv.First(tagOctet); child != nil {
		out.ErrorResponse = copyBytes(child.Value)
	}
	*e = out
	return nil
}

func profileInstallationSucceeded(tlv *bertlv.TLV) (bool, error) {
	if err := expectTag(tlv, tagProfileInstall); err != nil {
		return false, err
	}
	data := tlv.First(tagProfileInstallData)
	if data == nil {
		return false, errors.New("asn1: ProfileInstallationResult missing ProfileInstallationResultData")
	}
	finalResult := data.First(tagProfileFinalResult)
	if finalResult == nil {
		return false, errors.New("asn1: ProfileInstallationResultData missing finalResult")
	}
	succeeded, ok := finalResultSucceeded(finalResult.Children)
	if !ok {
		return false, errors.New("asn1: cannot determine ProfileInstallationResult finalResult outcome")
	}
	return succeeded, nil
}

func finalResultSucceeded(children []*bertlv.TLV) (bool, bool) {
	if len(children) == 0 {
		return false, false
	}
	first := children[0]
	switch {
	case first.Tag.ContextSpecific() && first.Tag.Value() == 0:
		return true, true
	case first.Tag.ContextSpecific() && first.Tag.Value() == 1:
		return false, true
	case first.Tag.Equal(tagSequence):
		return finalResultSucceeded(first.Children)
	case first.Tag.Equal(bertlv.Application.Primitive(15)):
		return true, true
	case first.Tag.Equal(tagInteger):
		return false, true
	default:
		return false, false
	}
}

func profileDownloadResultData(tlv *bertlv.TLV) *bertlv.TLV {
	for _, child := range tlv.Children {
		if child.Tag.Equal(bertlv.ContextSpecific.Primitive(2)) {
			continue
		}
		return child
	}
	return nil
}

// SequenceNumber is SGP.32 SequenceNumber.
type SequenceNumber int64

// EimAcknowledgements is SGP.32 EimAcknowledgements, tag BF53.
type EimAcknowledgements struct {
	SequenceNumbers []SequenceNumber
}

// MarshalBERTLV encodes EimAcknowledgements.
func (a *EimAcknowledgements) MarshalBERTLV() (*bertlv.TLV, error) {
	if a == nil {
		return nil, errors.New("asn1: nil EimAcknowledgements")
	}
	children := make([]*bertlv.TLV, 0, len(a.SequenceNumbers))
	for _, number := range a.SequenceNumbers {
		child, err := integerTLV(bertlv.ContextSpecific.Primitive(0), number)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return constructed(tagEimAck, children...), nil
}

// UnmarshalBERTLV decodes EimAcknowledgements.
func (a *EimAcknowledgements) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagEimAck); err != nil {
		return err
	}
	out := EimAcknowledgements{SequenceNumbers: make([]SequenceNumber, 0, len(tlv.Children))}
	for _, child := range tlv.Children {
		if err := expectTag(child, bertlv.ContextSpecific.Primitive(0)); err != nil {
			return err
		}
		number, err := integerValue[SequenceNumber](child)
		if err != nil {
			return err
		}
		out.SequenceNumbers = append(out.SequenceNumbers, number)
	}
	*a = out
	return nil
}

// EuiccPackageResultKind identifies the selected EuiccPackageResult CHOICE.
type EuiccPackageResultKind int

const (
	// EuiccPackageResultOK selects euiccPackageResultSigned.
	EuiccPackageResultOK EuiccPackageResultKind = iota + 1
	// EuiccPackageResultErrorSigned selects euiccPackageErrorSigned.
	EuiccPackageResultErrorSigned
	// EuiccPackageResultErrorUnsigned selects euiccPackageErrorUnsigned.
	EuiccPackageResultErrorUnsigned
)

// EuiccPackageResult is SGP.32 EuiccPackageResult, tag BF51.
type EuiccPackageResult struct {
	Kind          EuiccPackageResultKind
	Signed        *EuiccPackageResultSigned
	ErrorSigned   *EuiccPackageErrorSigned
	ErrorUnsigned *EuiccPackageErrorUnsigned
}

// MarshalBERTLV encodes EuiccPackageResult.
func (r *EuiccPackageResult) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil EuiccPackageResult")
	}
	var child *bertlv.TLV
	var err error
	switch r.Kind {
	case EuiccPackageResultOK:
		if r.Signed == nil {
			return nil, errors.New("asn1: missing signed eUICC package result")
		}
		child, err = r.Signed.MarshalBERTLV()
	case EuiccPackageResultErrorSigned:
		if r.ErrorSigned == nil {
			return nil, errors.New("asn1: missing signed eUICC package error")
		}
		child, err = r.ErrorSigned.MarshalBERTLV()
	case EuiccPackageResultErrorUnsigned:
		if r.ErrorUnsigned == nil {
			return nil, errors.New("asn1: missing unsigned eUICC package error")
		}
		child, err = r.ErrorUnsigned.MarshalBERTLV()
	default:
		return nil, fmt.Errorf("asn1: unknown EuiccPackageResult kind %d", r.Kind)
	}
	if err != nil {
		return nil, err
	}
	return constructed(tagEuiccPkg, child), nil
}

// UnmarshalBERTLV decodes EuiccPackageResult.
func (r *EuiccPackageResult) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagEuiccPkg); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: EuiccPackageResult requires one selected child")
	}
	child := tlv.Children[0]
	var out EuiccPackageResult
	if child.First(tagSignature) != nil {
		if len(child.Children) == 0 {
			return errors.New("asn1: signed EuiccPackageResult child is empty")
		}
		first := child.Children[0]
		if first.First(bertlv.ContextSpecific.Primitive(3)) != nil {
			out.Kind = EuiccPackageResultOK
			out.Signed = new(EuiccPackageResultSigned)
			if err := out.Signed.UnmarshalBERTLV(child); err != nil {
				return err
			}
		} else {
			out.Kind = EuiccPackageResultErrorSigned
			out.ErrorSigned = new(EuiccPackageErrorSigned)
			if err := out.ErrorSigned.UnmarshalBERTLV(child); err != nil {
				return err
			}
		}
	} else {
		out.Kind = EuiccPackageResultErrorUnsigned
		out.ErrorUnsigned = new(EuiccPackageErrorUnsigned)
		if err := out.ErrorUnsigned.UnmarshalBERTLV(child); err != nil {
			return err
		}
	}
	*r = out
	return nil
}

// EuiccPackageResultSigned is SGP.32 EuiccPackageResultSigned.
type EuiccPackageResultSigned struct {
	Data         EuiccPackageResultDataSigned
	EuiccSignEPR []byte
}

// MarshalBERTLV encodes EuiccPackageResultSigned.
func (r *EuiccPackageResultSigned) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil EuiccPackageResultSigned")
	}
	data, err := r.Data.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	return constructed(tagSequence, data, octetTLV(tagSignature, r.EuiccSignEPR)), nil
}

// UnmarshalBERTLV decodes EuiccPackageResultSigned.
func (r *EuiccPackageResultSigned) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	if len(tlv.Children) < 2 {
		return errors.New("asn1: signed result requires data and signature")
	}
	var out EuiccPackageResultSigned
	if err := out.Data.UnmarshalBERTLV(tlv.Children[0]); err != nil {
		return err
	}
	signature, err := octetValue(tlv.First(tagSignature))
	if err != nil {
		return err
	}
	out.EuiccSignEPR = signature
	*r = out
	return nil
}

// EuiccPackageResultDataSigned is SGP.32 EuiccPackageResultDataSigned.
type EuiccPackageResultDataSigned struct {
	EimID            string
	CounterValue     int64
	EimTransactionID []byte
	SeqNumber        int64
	Results          []EuiccResultData
}

// MarshalBERTLV encodes EuiccPackageResultDataSigned.
func (d *EuiccPackageResultDataSigned) MarshalBERTLV() (*bertlv.TLV, error) {
	if d == nil {
		return nil, errors.New("asn1: nil EuiccPackageResultDataSigned")
	}
	counter, err := integerTLV(bertlv.ContextSpecific.Primitive(1), d.CounterValue)
	if err != nil {
		return nil, err
	}
	seq, err := integerTLV(bertlv.ContextSpecific.Primitive(3), d.SeqNumber)
	if err != nil {
		return nil, err
	}
	resultChildren := make([]*bertlv.TLV, 0, len(d.Results))
	for index := range d.Results {
		child, err := d.Results[index].MarshalBERTLV()
		if err != nil {
			return nil, err
		}
		resultChildren = append(resultChildren, child)
	}
	children := []*bertlv.TLV{
		utf8TLV(bertlv.ContextSpecific.Primitive(0), d.EimID),
		counter,
	}
	if d.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(2), d.EimTransactionID))
	}
	children = append(children, seq, constructed(tagSequence, resultChildren...))
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes EuiccPackageResultDataSigned.
func (d *EuiccPackageResultDataSigned) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	var out EuiccPackageResultDataSigned
	var err error
	if out.EimID, err = utf8Value(tlv.First(bertlv.ContextSpecific.Primitive(0))); err != nil {
		return err
	}
	if out.CounterValue, err = integerValue[int64](tlv.First(bertlv.ContextSpecific.Primitive(1))); err != nil {
		return err
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		out.EimTransactionID = copyBytes(child.Value)
	}
	if out.SeqNumber, err = integerValue[int64](tlv.First(bertlv.ContextSpecific.Primitive(3))); err != nil {
		return err
	}
	if len(tlv.Children) == 0 {
		return errors.New("asn1: EuiccPackageResultDataSigned is empty")
	}
	resultList := tlv.Children[len(tlv.Children)-1]
	if err := expectTag(resultList, tagSequence); err != nil {
		return err
	}
	out.Results = make([]EuiccResultData, 0, len(resultList.Children))
	for _, child := range resultList.Children {
		var result EuiccResultData
		if err := result.UnmarshalBERTLV(child); err != nil {
			return err
		}
		out.Results = append(out.Results, result)
	}
	*d = out
	return nil
}

// EuiccResultData is one SGP.32 EuiccResultData CHOICE value.
type EuiccResultData struct {
	Raw *bertlv.TLV
}

// MarshalBERTLV encodes EuiccResultData.
func (r *EuiccResultData) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil || r.Raw == nil {
		return nil, errors.New("asn1: missing EuiccResultData TLV")
	}
	return cloneTLV(r.Raw), nil
}

// UnmarshalBERTLV decodes EuiccResultData.
func (r *EuiccResultData) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing EuiccResultData")
	}
	if !isEuiccResultDataTLV(tlv) {
		return fmt.Errorf("%w: unknown EuiccResultData tag %s", errUnexpectedTag, tlv.Tag.String())
	}
	r.Raw = cloneTLV(tlv)
	return nil
}

// IntegerEuiccResult builds an INTEGER EuiccResultData alternative with the
// given context-specific tag number.
func IntegerEuiccResult(tagNumber uint64, value int64) (EuiccResultData, error) {
	tlv, err := integerTLV(bertlv.ContextSpecific.Primitive(tagNumber), value)
	if err != nil {
		return EuiccResultData{}, err
	}
	return EuiccResultData{Raw: tlv}, nil
}

// AddEimEuiccResult builds the explicit addEimResult EuiccResultData wrapper.
func AddEimEuiccResult(result *AddEimResult) (EuiccResultData, error) {
	return explicitEuiccResult(bertlv.ContextSpecific.Constructed(8), result)
}

// ListEimEuiccResult builds the explicit listEimResult EuiccResultData wrapper.
func ListEimEuiccResult(result *ListEimResult) (EuiccResultData, error) {
	return explicitEuiccResult(bertlv.ContextSpecific.Constructed(11), result)
}

// SetDefaultDPAddressEuiccResult builds the setDefaultDpAddressResult EuiccResultData value.
func SetDefaultDPAddressEuiccResult(result *SetDefaultDPAddressResponse) (EuiccResultData, error) {
	if result == nil {
		return EuiccResultData{}, errors.New("asn1: nil SetDefaultDPAddressResponse")
	}
	raw, err := result.MarshalBERTLV()
	if err != nil {
		return EuiccResultData{}, err
	}
	return EuiccResultData{Raw: raw}, nil
}

func explicitEuiccResult(tag bertlv.Tag, value Marshaler) (EuiccResultData, error) {
	child, err := value.MarshalBERTLV()
	if err != nil {
		return EuiccResultData{}, err
	}
	return EuiccResultData{Raw: constructed(tag, child)}, nil
}

func isEuiccResultDataTLV(tlv *bertlv.TLV) bool {
	if tlv == nil {
		return false
	}
	if tlv.Tag.Equal(tagProfileInfoList) || tlv.Tag.Equal(tagSetDefaultDPAddress) {
		return true
	}
	if !tlv.Tag.ContextSpecific() {
		return false
	}
	switch tlv.Tag.Value() {
	case 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15:
		return true
	default:
		return false
	}
}

// EuiccPackageErrorSigned is SGP.32 EuiccPackageErrorSigned.
type EuiccPackageErrorSigned struct {
	Data         EuiccPackageErrorDataSigned
	EuiccSignEPE []byte
}

// MarshalBERTLV encodes EuiccPackageErrorSigned.
func (e *EuiccPackageErrorSigned) MarshalBERTLV() (*bertlv.TLV, error) {
	if e == nil {
		return nil, errors.New("asn1: nil EuiccPackageErrorSigned")
	}
	data, err := e.Data.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	return constructed(tagSequence, data, octetTLV(tagSignature, e.EuiccSignEPE)), nil
}

// UnmarshalBERTLV decodes EuiccPackageErrorSigned.
func (e *EuiccPackageErrorSigned) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	if len(tlv.Children) < 2 {
		return errors.New("asn1: signed error requires data and signature")
	}
	var out EuiccPackageErrorSigned
	if err := out.Data.UnmarshalBERTLV(tlv.Children[0]); err != nil {
		return err
	}
	signature, err := octetValue(tlv.First(tagSignature))
	if err != nil {
		return err
	}
	out.EuiccSignEPE = signature
	*e = out
	return nil
}

// EuiccPackageErrorDataSigned is SGP.32 EuiccPackageErrorDataSigned.
type EuiccPackageErrorDataSigned struct {
	EimID            string
	CounterValue     int64
	EimTransactionID []byte
	ErrorCode        EuiccPackageErrorCode
}

// MarshalBERTLV encodes EuiccPackageErrorDataSigned.
func (e *EuiccPackageErrorDataSigned) MarshalBERTLV() (*bertlv.TLV, error) {
	if e == nil {
		return nil, errors.New("asn1: nil EuiccPackageErrorDataSigned")
	}
	counter, err := integerTLV(bertlv.ContextSpecific.Primitive(1), e.CounterValue)
	if err != nil {
		return nil, err
	}
	code, err := integerTLV(tagInteger, e.ErrorCode)
	if err != nil {
		return nil, err
	}
	children := []*bertlv.TLV{utf8TLV(bertlv.ContextSpecific.Primitive(0), e.EimID), counter}
	if e.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(2), e.EimTransactionID))
	}
	children = append(children, code)
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes EuiccPackageErrorDataSigned.
func (e *EuiccPackageErrorDataSigned) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	var out EuiccPackageErrorDataSigned
	var err error
	if out.EimID, err = utf8Value(tlv.First(bertlv.ContextSpecific.Primitive(0))); err != nil {
		return err
	}
	if out.CounterValue, err = integerValue[int64](tlv.First(bertlv.ContextSpecific.Primitive(1))); err != nil {
		return err
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		out.EimTransactionID = copyBytes(child.Value)
	}
	if out.ErrorCode, err = integerValue[EuiccPackageErrorCode](tlv.First(tagInteger)); err != nil {
		return err
	}
	*e = out
	return nil
}

// EuiccPackageErrorUnsigned is SGP.32 EuiccPackageErrorUnsigned.
type EuiccPackageErrorUnsigned struct {
	EimID            string
	EimTransactionID []byte
	AssociationToken *int64
	ErrorCode        *EuiccPackageUnsignedErrorCode
}

// MarshalBERTLV encodes EuiccPackageErrorUnsigned.
func (e *EuiccPackageErrorUnsigned) MarshalBERTLV() (*bertlv.TLV, error) {
	if e == nil {
		return nil, errors.New("asn1: nil EuiccPackageErrorUnsigned")
	}
	children := []*bertlv.TLV{utf8TLV(bertlv.ContextSpecific.Primitive(0), e.EimID)}
	if e.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(2), e.EimTransactionID))
	}
	if e.AssociationToken != nil {
		token, err := integerTLV(bertlv.ContextSpecific.Primitive(4), *e.AssociationToken)
		if err != nil {
			return nil, err
		}
		children = append(children, token)
	}
	if e.ErrorCode != nil {
		code, err := integerTLV(bertlv.ContextSpecific.Primitive(15), *e.ErrorCode)
		if err != nil {
			return nil, err
		}
		children = append(children, code)
	}
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes EuiccPackageErrorUnsigned.
func (e *EuiccPackageErrorUnsigned) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	var out EuiccPackageErrorUnsigned
	var err error
	if out.EimID, err = utf8Value(tlv.First(bertlv.ContextSpecific.Primitive(0))); err != nil {
		return err
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		out.EimTransactionID = copyBytes(child.Value)
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(4)); child != nil {
		value, err := integerValue[int64](child)
		if err != nil {
			return err
		}
		out.AssociationToken = &value
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(15)); child != nil {
		value, err := integerValue[EuiccPackageUnsignedErrorCode](child)
		if err != nil {
			return err
		}
		out.ErrorCode = &value
	}
	*e = out
	return nil
}

// ProfileState is the imported SGP.22 ProfileState INTEGER used in ProfileInfo.
type ProfileState int64

const (
	// ProfileStateDisabled means the profile is installed but disabled.
	ProfileStateDisabled ProfileState = 0
	// ProfileStateEnabled means the profile is installed and enabled.
	ProfileStateEnabled ProfileState = 1
)

// ProfileInfo is the subset of SGP.32/SGP.22 ProfileInfo that the eIM persists.
type ProfileInfo struct {
	ICCID             []byte
	ProfileState      *ProfileState
	FallbackAttribute bool
}

// MarshalBERTLV encodes ProfileInfo as tag E3.
func (p *ProfileInfo) MarshalBERTLV() (*bertlv.TLV, error) {
	if p == nil {
		return nil, errors.New("asn1: nil ProfileInfo")
	}
	var children []*bertlv.TLV
	if p.ICCID != nil {
		children = append(children, octetTLV(tagEID, p.ICCID))
	}
	if p.ProfileState != nil {
		child, err := integerTLV(tagProfileState, *p.ProfileState)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if p.FallbackAttribute {
		child, err := booleanTLV(tagFallbackAttribute, true)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return constructed(tagProfileInfo, children...), nil
}

// UnmarshalBERTLV decodes the persisted subset of ProfileInfo from tag E3.
func (p *ProfileInfo) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagProfileInfo); err != nil {
		return err
	}
	var out ProfileInfo
	var err error
	if child := tlv.First(tagEID); child != nil {
		out.ICCID, err = octetValue(child)
		if err != nil {
			return err
		}
	}
	if child := tlv.First(tagProfileState); child != nil {
		value, err := integerValue[ProfileState](child)
		if err != nil {
			return err
		}
		out.ProfileState = &value
	}
	if child := tlv.First(tagFallbackAttribute); child != nil {
		out.FallbackAttribute, err = booleanValue(child)
		if err != nil {
			return err
		}
	}
	*p = out
	return nil
}

// ProfileInfoListResponse is SGP.32 ProfileInfoListResponse, tag BF2D.
type ProfileInfoListResponse struct {
	Profiles []ProfileInfo
	Error    *ProfileInfoListError
}

// MarshalBERTLV encodes ProfileInfoListResponse.
func (r *ProfileInfoListResponse) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil ProfileInfoListResponse")
	}
	if r.Error != nil {
		child, err := integerTLV(tagInteger, *r.Error)
		if err != nil {
			return nil, err
		}
		return constructed(tagProfileInfoList, child), nil
	}
	profiles := make([]*bertlv.TLV, 0, len(r.Profiles))
	for index := range r.Profiles {
		profile, err := r.Profiles[index].MarshalBERTLV()
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return constructed(tagProfileInfoList, constructed(tagSequence, profiles...)), nil
}

// UnmarshalBERTLV decodes ProfileInfoListResponse.
func (r *ProfileInfoListResponse) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagProfileInfoList); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: ProfileInfoListResponse requires one selected child")
	}
	child := tlv.Children[0]
	var out ProfileInfoListResponse
	if hasTag(child, tagInteger) {
		value, err := integerValue[ProfileInfoListError](child)
		if err != nil {
			return err
		}
		out.Error = &value
	} else {
		if err := expectTag(child, tagSequence); err != nil {
			return err
		}
		out.Profiles = make([]ProfileInfo, 0, len(child.Children))
		for _, profile := range child.Children {
			var decoded ProfileInfo
			if err := decoded.UnmarshalBERTLV(profile); err != nil {
				return err
			}
			out.Profiles = append(out.Profiles, decoded)
		}
	}
	*r = out
	return nil
}

// ProfileInfoListEuiccResult builds the listProfileInfoResult EuiccResultData value.
func ProfileInfoListEuiccResult(result *ProfileInfoListResponse) (EuiccResultData, error) {
	if result == nil {
		return EuiccResultData{}, errors.New("asn1: nil ProfileInfoListResponse")
	}
	raw, err := result.MarshalBERTLV()
	if err != nil {
		return EuiccResultData{}, err
	}
	return EuiccResultData{Raw: raw}, nil
}

// AddEimResult is SGP.32 AddEimResult.
type AddEimResult struct {
	AssociationToken *int64
	Code             *AddEimResultCode
}

// MarshalBERTLV encodes AddEimResult.
func (r *AddEimResult) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil AddEimResult")
	}
	if r.AssociationToken != nil {
		return integerTLV(bertlv.ContextSpecific.Primitive(4), *r.AssociationToken)
	}
	if r.Code != nil {
		return integerTLV(tagInteger, *r.Code)
	}
	return nil, errors.New("asn1: AddEimResult requires association token or code")
}

// UnmarshalBERTLV decodes AddEimResult.
func (r *AddEimResult) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing AddEimResult")
	}
	var out AddEimResult
	if hasTag(tlv, bertlv.ContextSpecific.Primitive(4)) {
		value, err := integerValue[int64](tlv)
		if err != nil {
			return err
		}
		out.AssociationToken = &value
	} else if hasTag(tlv, tagInteger) {
		value, err := integerValue[AddEimResultCode](tlv)
		if err != nil {
			return err
		}
		out.Code = &value
	} else {
		return fmt.Errorf("%w: unknown AddEimResult tag %s", errUnexpectedTag, tlv.Tag.String())
	}
	*r = out
	return nil
}

// EimIDInfo is SGP.32 EimIdInfo.
type EimIDInfo struct {
	EimID     string
	EimIDType *EimIDType
}

// MarshalBERTLV encodes EimIDInfo.
func (i *EimIDInfo) MarshalBERTLV() (*bertlv.TLV, error) {
	if i == nil {
		return nil, errors.New("asn1: nil EimIDInfo")
	}
	children := []*bertlv.TLV{utf8TLV(bertlv.ContextSpecific.Primitive(0), i.EimID)}
	if i.EimIDType != nil {
		child, err := integerTLV(bertlv.ContextSpecific.Primitive(2), *i.EimIDType)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes EimIDInfo.
func (i *EimIDInfo) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	var out EimIDInfo
	var err error
	if out.EimID, err = utf8Value(tlv.First(bertlv.ContextSpecific.Primitive(0))); err != nil {
		return err
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		value, err := integerValue[EimIDType](child)
		if err != nil {
			return err
		}
		out.EimIDType = &value
	}
	*i = out
	return nil
}

// ListEimResult is SGP.32 ListEimResult.
type ListEimResult struct {
	EimIDList []EimIDInfo
	Error     *ListEimError
}

// MarshalBERTLV encodes ListEimResult.
func (r *ListEimResult) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil ListEimResult")
	}
	if r.Error != nil {
		return integerTLV(tagInteger, *r.Error)
	}
	children := make([]*bertlv.TLV, 0, len(r.EimIDList))
	for index := range r.EimIDList {
		child, err := r.EimIDList[index].MarshalBERTLV()
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes ListEimResult.
func (r *ListEimResult) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing ListEimResult")
	}
	var out ListEimResult
	if hasTag(tlv, tagInteger) {
		value, err := integerValue[ListEimError](tlv)
		if err != nil {
			return err
		}
		out.Error = &value
	} else {
		if err := expectTag(tlv, tagSequence); err != nil {
			return err
		}
		out.EimIDList = make([]EimIDInfo, 0, len(tlv.Children))
		for _, child := range tlv.Children {
			var info EimIDInfo
			if err := info.UnmarshalBERTLV(child); err != nil {
				return err
			}
			out.EimIDList = append(out.EimIDList, info)
		}
	}
	*r = out
	return nil
}

// EuiccPackageErrorCode is SGP.32 EuiccPackageErrorCode.
type EuiccPackageErrorCode int64

// EuiccPackageUnsignedErrorCode is SGP.32 EuiccPackageUnsignedErrorCode.
type EuiccPackageUnsignedErrorCode int64

// ProfileInfoListError is SGP.32 ProfileInfoListError.
type ProfileInfoListError int64

// AddEimResultCode is the INTEGER branch of SGP.32 AddEimResult.
type AddEimResultCode int64

// ListEimError is the INTEGER branch of SGP.32 ListEimResult.
type ListEimError int64

// Result enumerations from SGP.32 EuiccResultData.
type (
	ConfigureImmediateEnableResult int64
	EnableProfileResult            int64
	DisableProfileResult           int64
	DeleteProfileResult            int64
	RollbackProfileResult          int64
	SetFallbackAttributeResult     int64
	UnsetFallbackAttributeResult   int64
	DeleteEimResult                int64
	UpdateEimResult                int64
)
