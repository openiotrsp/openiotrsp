// Package ipadata builds and consumes SGP.32 IPA-directed eUICC data reads.
package ipadata

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
)

// DefaultTagList asks the IPA for the data objects OpenIoTRSP can currently
// consume: eUICCInfo1/2, profile inventory, certificates, and IPA capabilities.
// EID (tag 5A / application 26) is excluded: SGP.32 IpaEuiccDataRequest.tagList
// lists data-object tags to return in IpaEuiccData, and the IPA already knows the
// target EID from ESipa context.
var DefaultTagList = []byte{0xbf, 0x20, 0xbf, 0x22, 0xbf, 0x2d, 0xa5, 0xa6, 0xa8}

// RequestInput configures one IpaEuiccDataRequest.
type RequestInput struct {
	TagList                     []byte
	EUICCCIPKIdentifierToBeUsed []byte
	NotificationSeqNumber       *int64
	EuiccPackageResultSeqNumber *int64
	EimTransactionID            []byte
}

// NewRequest constructs an IPA-directed eUICC data request. It intentionally
// does not sign or wrap the request as an eUICC Package.
func NewRequest(input RequestInput) (*protocolasn1.IpaEuiccDataRequest, error) {
	tagList := cloneBytes(input.TagList)
	if len(tagList) == 0 {
		tagList = cloneBytes(DefaultTagList)
	}
	if len(tagList) == 0 {
		return nil, errors.New("ipadata: tagList is required")
	}
	request := &protocolasn1.IpaEuiccDataRequest{
		TagList:                     tagList,
		EUICCCIPKIdentifierToBeUsed: cloneBytes(input.EUICCCIPKIdentifierToBeUsed),
		EimTransactionID:            cloneBytes(input.EimTransactionID),
	}
	if input.NotificationSeqNumber != nil {
		value := *input.NotificationSeqNumber
		request.SearchCriteriaNotification = &protocolasn1.IpaEuiccDataNotificationSearchCriteria{
			SeqNumber: &value,
		}
	}
	if input.EuiccPackageResultSeqNumber != nil {
		request.SearchCriteriaEuiccPackageResult = &protocolasn1.IpaEuiccDataPackageResultSearchCriteria{
			SeqNumber: *input.EuiccPackageResultSeqNumber,
		}
	}
	return request, nil
}

// EnqueueRequest stores one BF52 data request for ESipa delivery.
func EnqueueRequest(ctx context.Context, store storage.Store, tenantID storage.TenantID, eid string, input RequestInput) (storage.Operation, error) {
	if store == nil {
		return storage.Operation{}, errors.New("ipadata: nil Store")
	}
	request, err := NewRequest(input)
	if err != nil {
		return storage.Operation{}, err
	}
	payload, err := protocolasn1.Encode(request)
	if err != nil {
		return storage.Operation{}, fmt.Errorf("encode IpaEuiccDataRequest: %w", err)
	}
	return store.EnqueueOperation(ctx, tenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationIpaEuiccData,
		Payload: payload,
	})
}

// ApplyResponse persists the current eUICC view returned by an IPA data read.
// BF52 data responses are informational ESipa data, not signed eUICC Package
// Results. The persisted state must remain an observability/reconciliation view
// and must not be used as authorization evidence without another trust check.
func ApplyResponse(ctx context.Context, store storage.Store, tenantID storage.TenantID, eid string, response *protocolasn1.IpaEuiccDataResponse, payload []byte) error {
	if response == nil || response.Data == nil {
		return nil
	}
	state, err := StateFromResponse(eid, response, payload)
	if err != nil {
		return err
	}
	if err := store.SetEUICCState(ctx, tenantID, state); err != nil {
		return err
	}
	return syncProfileInventory(ctx, store, tenantID, eid, response.Data)
}

func syncProfileInventory(ctx context.Context, store storage.Store, tenantID storage.TenantID, eid string, data *protocolasn1.IpaEuiccData) error {
	if data == nil || !data.ProfileInfoListPresent && len(data.Profiles) == 0 {
		return nil
	}
	existing, err := store.ListProfileStates(ctx, tenantID, eid)
	if err != nil {
		return err
	}
	existingByICCID := make(map[string]storage.ProfileState, len(existing))
	for _, state := range existing {
		existingByICCID[state.ICCID] = state
	}
	seen := make(map[string]bool, len(data.Profiles))
	for _, profile := range data.Profiles {
		if len(profile.ICCID) == 0 {
			continue
		}
		iccid := hex.EncodeToString(profile.ICCID)
		seen[iccid] = true
		enabled := false
		if profile.ProfileState != nil {
			enabled = *profile.ProfileState == protocolasn1.ProfileStateEnabled
		}
		state := existingByICCID[iccid]
		state.EID = eid
		state.ICCID = iccid
		state.IsEnabled = enabled
		state.IsFallback = profile.FallbackAttribute
		if err := store.SetProfileState(ctx, tenantID, state); err != nil {
			return err
		}
	}
	for _, state := range existing {
		if seen[state.ICCID] {
			continue
		}
		if err := store.DeleteProfileState(ctx, tenantID, eid, state.ICCID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	return nil
}

// StateFromResponse maps an IpaEuiccDataResponse into the Store's current
// eUICC-state record.
func StateFromResponse(eid string, response *protocolasn1.IpaEuiccDataResponse, payload []byte) (storage.EUICCState, error) {
	if response == nil || response.Data == nil {
		return storage.EUICCState{}, errors.New("ipadata: response contains no eUICC data")
	}
	data := response.Data
	if len(data.EID) == 16 {
		eid = hex.EncodeToString(data.EID)
	}
	state := storage.EUICCState{
		EID:                    eid,
		EIDValue:               cloneBytes(data.EID),
		DefaultSMDPAddress:     stringValue(data.DefaultSMDPAddress),
		RootSMDSAddress:        stringValue(data.RootSMDSAddress),
		EUICCInfo1:             marshalRaw(data.EUICCInfo1Raw),
		EUICCInfo2:             marshalRaw(data.EUICCInfo2Raw),
		IPACapabilities:        marshalRaw(data.IPACapabilitiesRaw),
		DeviceInfo:             marshalRaw(data.DeviceInfoRaw),
		EUMCertificate:         marshalRaw(data.EUMCertificateRaw),
		EUICCCertificate:       marshalRaw(data.EUICCCertificateRaw),
		CertificateIdentifiers: certificateIdentifiers(data),
		RawPayload:             cloneBytes(payload),
	}
	return state, nil
}

func certificateIdentifiers(data *protocolasn1.IpaEuiccData) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id []byte) {
		if len(id) == 0 {
			return
		}
		value := hex.EncodeToString(id)
		if seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	addInfo := func(info *protocolasn1.EUICCInfo) {
		if info == nil {
			return
		}
		for _, id := range info.VerificationCIPKIDs {
			add(id)
		}
		for _, id := range info.SigningCIPKIDs {
			add(id)
		}
		for _, id := range info.SigningV3CIPKIDs {
			add(id)
		}
	}
	addInfo(data.EUICCInfo1)
	addInfo(data.EUICCInfo2)
	add(certificateSubjectKeyID(data.EUMCertificateRaw))
	add(certificateSubjectKeyID(data.EUICCCertificateRaw))
	return out
}

func certificateSubjectKeyID(tlv *protocolasn1.TLV) []byte {
	if tlv == nil || len(tlv.Children) == 0 {
		return nil
	}
	der, err := tlv.Children[0].MarshalBinary()
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert.SubjectKeyId
}

func marshalRaw(tlv *protocolasn1.TLV) []byte {
	if tlv == nil {
		return nil
	}
	raw, err := tlv.MarshalBinary()
	if err != nil {
		return nil
	}
	return raw
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
