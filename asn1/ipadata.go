package asn1

import (
	"errors"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
)

var (
	tagTagList         = bertlv.Application.Primitive(28)
	tagEUICCInfo1      = bertlv.ContextSpecific.Constructed(32)
	tagEUICCInfo2      = bertlv.ContextSpecific.Constructed(34)
	tagIPACapabilities = bertlv.ContextSpecific.Constructed(8)
)

// IpaEuiccDataErrorCode is SGP.32 IpaEuiccDataErrorCode.
type IpaEuiccDataErrorCode int64

// IpaEuiccDataRequest is SGP.32 IpaEuiccDataRequest, tag BF52.
type IpaEuiccDataRequest struct {
	TagList                          []byte
	EUICCCIPKIdentifierToBeUsed      []byte
	SearchCriteriaNotification       *IpaEuiccDataNotificationSearchCriteria
	SearchCriteriaEuiccPackageResult *IpaEuiccDataPackageResultSearchCriteria
	EimTransactionID                 []byte
}

// IpaEuiccDataNotificationSearchCriteria models the currently consumed
// notification search criteria. Profile-management-operation criteria are kept
// as raw TLV until the imported NotificationEvent model is needed.
type IpaEuiccDataNotificationSearchCriteria struct {
	SeqNumber                     *int64
	ProfileManagementOperationRaw *bertlv.TLV
}

// IpaEuiccDataPackageResultSearchCriteria models package-result lookup by
// sequence number.
type IpaEuiccDataPackageResultSearchCriteria struct {
	SeqNumber int64
}

// MarshalBERTLV encodes IpaEuiccDataRequest.
func (r *IpaEuiccDataRequest) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil IpaEuiccDataRequest")
	}
	if len(r.TagList) == 0 {
		return nil, errors.New("asn1: IpaEuiccDataRequest tagList is required")
	}
	children := []*bertlv.TLV{octetTLV(tagTagList, r.TagList)}
	if r.EUICCCIPKIdentifierToBeUsed != nil {
		children = append(children, octetTLV(tagOctet, r.EUICCCIPKIdentifierToBeUsed))
	}
	if r.SearchCriteriaNotification != nil {
		child, err := r.SearchCriteriaNotification.marshal()
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if r.SearchCriteriaEuiccPackageResult != nil {
		seq, err := integerTLV(bertlv.ContextSpecific.Primitive(0), r.SearchCriteriaEuiccPackageResult.SeqNumber)
		if err != nil {
			return nil, err
		}
		children = append(children, constructed(bertlv.ContextSpecific.Constructed(2), seq))
	}
	if r.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(3), r.EimTransactionID))
	}
	return constructed(tagIpaEuiccData, children...), nil
}

// UnmarshalBERTLV decodes IpaEuiccDataRequest.
func (r *IpaEuiccDataRequest) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagIpaEuiccData); err != nil {
		return err
	}
	var out IpaEuiccDataRequest
	var err error
	if out.TagList, err = octetValue(tlv.First(tagTagList)); err != nil {
		return err
	}
	if child := firstUniversalOctet(tlv.Children, tagTagList); child != nil {
		out.EUICCCIPKIdentifierToBeUsed, err = octetValue(child)
		if err != nil {
			return err
		}
	}
	if child := tlv.First(bertlv.ContextSpecific.Constructed(1)); child != nil {
		criteria := new(IpaEuiccDataNotificationSearchCriteria)
		if err := criteria.unmarshal(child); err != nil {
			return err
		}
		out.SearchCriteriaNotification = criteria
	}
	if child := tlv.First(bertlv.ContextSpecific.Constructed(2)); child != nil {
		seq, err := integerValue[int64](child.First(bertlv.ContextSpecific.Primitive(0)))
		if err != nil {
			return err
		}
		out.SearchCriteriaEuiccPackageResult = &IpaEuiccDataPackageResultSearchCriteria{SeqNumber: seq}
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(3)); child != nil {
		out.EimTransactionID, err = octetValue(child)
		if err != nil {
			return err
		}
	}
	*r = out
	return nil
}

func (c *IpaEuiccDataNotificationSearchCriteria) marshal() (*bertlv.TLV, error) {
	if c.SeqNumber != nil {
		seq, err := integerTLV(bertlv.ContextSpecific.Primitive(0), *c.SeqNumber)
		if err != nil {
			return nil, err
		}
		return constructed(bertlv.ContextSpecific.Constructed(1), seq), nil
	}
	if c.ProfileManagementOperationRaw != nil {
		return constructed(bertlv.ContextSpecific.Constructed(1), rawChild(c.ProfileManagementOperationRaw)), nil
	}
	return nil, errors.New("asn1: empty notification search criteria")
}

func (c *IpaEuiccDataNotificationSearchCriteria) unmarshal(tlv *bertlv.TLV) error {
	if len(tlv.Children) != 1 {
		return errors.New("asn1: notification search criteria requires one choice")
	}
	child := tlv.Children[0]
	switch {
	case hasTag(child, bertlv.ContextSpecific.Primitive(0)):
		seq, err := integerValue[int64](child)
		if err != nil {
			return err
		}
		c.SeqNumber = &seq
	case hasTag(child, bertlv.ContextSpecific.Primitive(1)):
		c.ProfileManagementOperationRaw = cloneTLV(child)
	default:
		return fmt.Errorf("%w: unknown notification search criteria tag %s", errUnexpectedTag, child.Tag.String())
	}
	return nil
}

// IpaEuiccDataResponse is SGP.32 IpaEuiccDataResponse, tag BF52.
type IpaEuiccDataResponse struct {
	Data  *IpaEuiccData
	Error *IpaEuiccDataResponseError
}

// IpaEuiccDataResponseError is SGP.32 IpaEuiccDataResponseError.
type IpaEuiccDataResponseError struct {
	EimTransactionID []byte
	Code             IpaEuiccDataErrorCode
}

// IpaEuiccData is the typed subset of SGP.32 IpaEuiccData that OpenIoTRSP
// currently consumes. Unknown data objects remain available through RawObjects.
type IpaEuiccData struct {
	EID                   []byte
	NotificationsRaw      *bertlv.TLV
	DefaultSMDPAddress    *string
	EuiccPackageResults   []EuiccPackageResult
	EuiccPackageResultRaw *bertlv.TLV
	EUICCInfo1            *EUICCInfo
	EUICCInfo1Raw         *bertlv.TLV
	EUICCInfo2            *EUICCInfo
	EUICCInfo2Raw         *bertlv.TLV
	RootSMDSAddress       *string
	AssociationToken      *int64
	EUMCertificateRaw     *bertlv.TLV
	EUICCCertificateRaw   *bertlv.TLV
	EimTransactionID      []byte
	IPACapabilities       *IPACapabilities
	IPACapabilitiesRaw    *bertlv.TLV
	DeviceInfoRaw         *bertlv.TLV
	Profiles              []ProfileInfo
	RawObjects            []*bertlv.TLV
}

// EUICCInfo is the consumed subset of SGP.22 EUICCInfo1/EUICCInfo2.
type EUICCInfo struct {
	ProfileVersion      []byte
	SVN                 []byte
	FirmwareVersion     []byte
	VerificationCIPKIDs [][]byte
	SigningCIPKIDs      [][]byte
	SigningV3CIPKIDs    [][]byte
	Raw                 *bertlv.TLV
}

// IPACapabilities is the consumed subset of SGP.32 IpaCapabilities.
type IPACapabilities struct {
	Features           []bool
	SupportedProtocols []bool
	Raw                *bertlv.TLV
}

// MarshalBERTLV encodes IpaEuiccDataResponse.
func (r *IpaEuiccDataResponse) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil IpaEuiccDataResponse")
	}
	if r.Error != nil {
		return r.Error.marshal()
	}
	if r.Data == nil {
		return nil, errors.New("asn1: IpaEuiccDataResponse requires data or error")
	}
	return r.Data.marshal()
}

// UnmarshalBERTLV decodes IpaEuiccDataResponse.
func (r *IpaEuiccDataResponse) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagIpaEuiccData); err != nil {
		return err
	}
	if tlv.First(tagInteger) != nil {
		var out IpaEuiccDataResponse
		out.Error = new(IpaEuiccDataResponseError)
		if err := out.Error.unmarshal(tlv); err != nil {
			return err
		}
		*r = out
		return nil
	}
	data := new(IpaEuiccData)
	if err := data.unmarshal(tlv); err != nil {
		return err
	}
	*r = IpaEuiccDataResponse{Data: data}
	return nil
}

func (e *IpaEuiccDataResponseError) marshal() (*bertlv.TLV, error) {
	children := make([]*bertlv.TLV, 0, 2)
	if e.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(0), e.EimTransactionID))
	}
	code, err := integerTLV(tagInteger, e.Code)
	if err != nil {
		return nil, err
	}
	children = append(children, code)
	return constructed(tagIpaEuiccData, children...), nil
}

func (e *IpaEuiccDataResponseError) unmarshal(tlv *bertlv.TLV) error {
	var out IpaEuiccDataResponseError
	var err error
	if child := tlv.First(bertlv.ContextSpecific.Primitive(0)); child != nil {
		out.EimTransactionID, err = octetValue(child)
		if err != nil {
			return err
		}
	}
	if out.Code, err = integerValue[IpaEuiccDataErrorCode](tlv.First(tagInteger)); err != nil {
		return err
	}
	*e = out
	return nil
}

func (d *IpaEuiccData) marshal() (*bertlv.TLV, error) {
	if len(d.RawObjects) > 0 {
		children := make([]*bertlv.TLV, 0, len(d.RawObjects))
		for _, child := range d.RawObjects {
			children = append(children, rawChild(child))
		}
		return constructed(tagIpaEuiccData, children...), nil
	}
	children := make([]*bertlv.TLV, 0)
	if d.EID != nil {
		children = append(children, octetTLV(tagEID, d.EID))
	}
	if d.DefaultSMDPAddress != nil {
		children = append(children, utf8TLV(bertlv.ContextSpecific.Primitive(1), *d.DefaultSMDPAddress))
	}
	if d.NotificationsRaw != nil {
		children = append(children, rawChild(d.NotificationsRaw))
	}
	if d.EuiccPackageResultRaw != nil {
		children = append(children, rawChild(d.EuiccPackageResultRaw))
	}
	if d.EUICCInfo1Raw != nil {
		children = append(children, rawChild(d.EUICCInfo1Raw))
	}
	if d.EUICCInfo2Raw != nil {
		children = append(children, rawChild(d.EUICCInfo2Raw))
	}
	if d.RootSMDSAddress != nil {
		children = append(children, utf8TLV(bertlv.ContextSpecific.Primitive(3), *d.RootSMDSAddress))
	}
	if d.AssociationToken != nil {
		child, err := integerTLV(bertlv.ContextSpecific.Primitive(4), *d.AssociationToken)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	for _, child := range []*bertlv.TLV{d.EUMCertificateRaw, d.EUICCCertificateRaw, d.IPACapabilitiesRaw, d.DeviceInfoRaw} {
		if child != nil {
			children = append(children, rawChild(child))
		}
	}
	if d.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(7), d.EimTransactionID))
	}
	if len(d.Profiles) > 0 {
		profiles, err := (&ProfileInfoListResponse{Profiles: d.Profiles}).MarshalBERTLV()
		if err != nil {
			return nil, err
		}
		children = append(children, profiles)
	}
	return constructed(tagIpaEuiccData, children...), nil
}

func (d *IpaEuiccData) unmarshal(tlv *bertlv.TLV) error {
	var out IpaEuiccData
	var err error
	out.RawObjects = make([]*bertlv.TLV, 0, len(tlv.Children))
	for _, child := range tlv.Children {
		out.RawObjects = append(out.RawObjects, cloneTLV(child))
		switch {
		case child.Tag.Equal(tagEID):
			out.EID, err = octetValue(child)
		case child.Tag.Equal(bertlv.ContextSpecific.Constructed(0)):
			out.NotificationsRaw = cloneTLV(child)
		case child.Tag.Equal(bertlv.ContextSpecific.Primitive(1)):
			value, valueErr := utf8Value(child)
			err = valueErr
			out.DefaultSMDPAddress = &value
		case child.Tag.Equal(bertlv.ContextSpecific.Constructed(2)):
			out.EuiccPackageResultRaw = cloneTLV(child)
			out.EuiccPackageResults, err = unmarshalEuiccPackageResultList(child)
			if err == nil {
				out.Profiles = append(out.Profiles, profilesFromPackageResults(out.EuiccPackageResults)...)
			}
		case child.Tag.Equal(tagEUICCInfo1):
			out.EUICCInfo1Raw = cloneTLV(child)
			out.EUICCInfo1, err = unmarshalEUICCInfo(child)
		case child.Tag.Equal(tagEUICCInfo2):
			out.EUICCInfo2Raw = cloneTLV(child)
			out.EUICCInfo2, err = unmarshalEUICCInfo(child)
		case child.Tag.Equal(bertlv.ContextSpecific.Primitive(3)):
			value, valueErr := utf8Value(child)
			err = valueErr
			out.RootSMDSAddress = &value
		case child.Tag.Equal(bertlv.ContextSpecific.Primitive(4)):
			value, valueErr := integerValue[int64](child)
			err = valueErr
			out.AssociationToken = &value
		case child.Tag.Equal(bertlv.ContextSpecific.Constructed(5)):
			out.EUMCertificateRaw = cloneTLV(child)
		case child.Tag.Equal(bertlv.ContextSpecific.Constructed(6)):
			out.EUICCCertificateRaw = cloneTLV(child)
		case child.Tag.Equal(bertlv.ContextSpecific.Primitive(7)):
			out.EimTransactionID, err = octetValue(child)
		case child.Tag.Equal(tagIPACapabilities):
			out.IPACapabilitiesRaw = cloneTLV(child)
			out.IPACapabilities, err = unmarshalIPACapabilities(child)
		case child.Tag.Equal(bertlv.ContextSpecific.Constructed(9)):
			out.DeviceInfoRaw = cloneTLV(child)
		case child.Tag.Equal(tagProfileInfoList):
			var profiles ProfileInfoListResponse
			err = profiles.UnmarshalBERTLV(child)
			if err == nil {
				out.Profiles = append(out.Profiles, profiles.Profiles...)
			}
		}
		if err != nil {
			return err
		}
	}
	*d = out
	return nil
}

func unmarshalEUICCInfo(tlv *bertlv.TLV) (*EUICCInfo, error) {
	info := &EUICCInfo{Raw: cloneTLV(tlv)}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(1)); child != nil {
		info.ProfileVersion = copyBytes(child.Value)
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		info.SVN = copyBytes(child.Value)
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(3)); child != nil {
		info.FirmwareVersion = copyBytes(child.Value)
	}
	info.VerificationCIPKIDs = subjectKeyIdentifiers(tlv.First(bertlv.ContextSpecific.Constructed(9)))
	info.SigningCIPKIDs = subjectKeyIdentifiers(tlv.First(bertlv.ContextSpecific.Constructed(10)))
	info.SigningV3CIPKIDs = subjectKeyIdentifiers(tlv.First(bertlv.ContextSpecific.Constructed(17)))
	return info, nil
}

func subjectKeyIdentifiers(tlv *bertlv.TLV) [][]byte {
	if tlv == nil {
		return nil
	}
	out := make([][]byte, 0, len(tlv.Children))
	for _, child := range tlv.Children {
		out = append(out, copyBytes(child.Value))
	}
	return out
}

func unmarshalIPACapabilities(tlv *bertlv.TLV) (*IPACapabilities, error) {
	out := &IPACapabilities{Raw: cloneTLV(tlv)}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(0)); child != nil {
		bits, err := bitStringValue(child)
		if err != nil {
			return nil, err
		}
		out.Features = bits
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(1)); child != nil {
		bits, err := bitStringValue(child)
		if err != nil {
			return nil, err
		}
		out.SupportedProtocols = bits
	}
	return out, nil
}

func unmarshalEuiccPackageResultList(tlv *bertlv.TLV) ([]EuiccPackageResult, error) {
	results := make([]EuiccPackageResult, 0, len(tlv.Children))
	for _, child := range tlv.Children {
		var result EuiccPackageResult
		if err := result.UnmarshalBERTLV(child); err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func profilesFromPackageResults(results []EuiccPackageResult) []ProfileInfo {
	var profiles []ProfileInfo
	for _, result := range results {
		if result.Kind != EuiccPackageResultOK || result.Signed == nil {
			continue
		}
		for _, item := range result.Signed.Data.Results {
			if item.Raw == nil || !item.Raw.Tag.Equal(tagProfileInfoList) {
				continue
			}
			var decoded ProfileInfoListResponse
			if err := decoded.UnmarshalBERTLV(item.Raw); err == nil {
				profiles = append(profiles, decoded.Profiles...)
			}
		}
	}
	return profiles
}

func firstUniversalOctet(children []*bertlv.TLV, skip bertlv.Tag) *bertlv.TLV {
	for _, child := range children {
		if child.Tag.Equal(skip) {
			continue
		}
		if child.Tag.Equal(tagOctet) {
			return child
		}
	}
	return nil
}
