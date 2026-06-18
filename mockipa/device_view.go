package mockipa

import (
	"bytes"
	"encoding/hex"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/pki"
)

type profileRecord struct {
	ICCID    []byte
	SMDP     string
	Enabled  bool
	Fallback bool
}

// ProfileRecord is one installed profile in the emulated eUICC inventory.
type ProfileRecord struct {
	ICCID    []byte
	SMDP     string
	Enabled  bool
	Fallback bool
}

// DeviceState is the mock IPA's view of on-device profile inventory.
type DeviceState struct {
	DefaultSMDP string
	RootSMDS    string
	Profiles    map[string]profileRecord
}

// NewDeviceState returns an empty emulated eUICC inventory.
func NewDeviceState() *DeviceState {
	return newDeviceState()
}

// SeedProfile inserts or replaces a profile for integration tests and demos.
func (s *DeviceState) SeedProfile(iccidHex string, enabled, fallback bool) {
	if s.Profiles == nil {
		s.Profiles = make(map[string]profileRecord)
	}
	iccid, err := hex.DecodeString(iccidHex)
	if err != nil || len(iccid) == 0 {
		iccid = []byte(iccidHex)
	}
	s.Profiles[iccidHex] = profileRecord{
		ICCID:    cloneBytes(iccid),
		Enabled:  enabled,
		Fallback: fallback,
	}
}

func newDeviceState() *DeviceState {
	return &DeviceState{
		RootSMDS: "smds.example",
		Profiles: make(map[string]profileRecord),
	}
}

func (s *DeviceState) recordDownload(profileID, smdp string) {
	iccid := profileIDToICCID(profileID)
	s.Profiles[hex.EncodeToString(iccid)] = profileRecord{
		ICCID:   iccid,
		SMDP:    smdp,
		Enabled: true,
	}
	if smdp != "" {
		s.DefaultSMDP = smdp
	}
}

func (s *DeviceState) applyPSMO(psmo protocolasn1.Psmo, enabled bool) {
	if len(psmo.ICCID) == 0 {
		return
	}
	key := hex.EncodeToString(psmo.ICCID)
	record := s.Profiles[key]
	record.ICCID = cloneBytes(psmo.ICCID)
	record.Enabled = enabled
	s.Profiles[key] = record
}

func (s *DeviceState) setProfileFallback(iccid []byte) {
	if len(iccid) == 0 {
		return
	}
	key := hex.EncodeToString(iccid)
	for profileKey, record := range s.Profiles {
		record.Fallback = profileKey == key
		s.Profiles[profileKey] = record
	}
	if _, ok := s.Profiles[key]; !ok {
		s.Profiles[key] = profileRecord{ICCID: cloneBytes(iccid), Fallback: true}
	}
}

func (s *DeviceState) clearProfileFallback() {
	for key, record := range s.Profiles {
		record.Fallback = false
		s.Profiles[key] = record
	}
}

func profileIDToICCID(profileID string) []byte {
	if decoded, err := hex.DecodeString(profileID); err == nil && len(decoded) > 0 {
		return decoded
	}
	return []byte(profileID)
}

func buildIpaEuiccDataResponse(eid []byte, fixture *SGP26Fixture, state *DeviceState, request *protocolasn1.IpaEuiccDataRequest) (*protocolasn1.IpaEuiccDataResponse, error) {
	if state == nil {
		state = newDeviceState()
	}
	tagList := []byte(nil)
	transactionID := []byte(nil)
	if request != nil {
		tagList = cloneBytes(request.TagList)
		transactionID = cloneBytes(request.EimTransactionID)
	}
	ciSubjectID, err := subjectKeyIDFromFixture(fixture)
	if err != nil {
		return nil, err
	}

	objects := make([]*bertlv.TLV, 0, 12)
	appendIfRequested := func(tag []byte, tlv *bertlv.TLV) {
		if tlv == nil {
			return
		}
		if tagListContains(tagList, tag) {
			objects = append(objects, tlv)
		}
	}
	appendIfRequested([]byte{0x5a}, bertlv.NewValue(bertlv.Application.Primitive(26), cloneBytes(eid)))
	if state.DefaultSMDP != "" {
		appendIfRequested([]byte{0x81}, bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte(state.DefaultSMDP)))
	}
	appendIfRequested([]byte{0xbf, 0x20}, sgp26EUICCInfo1(ciSubjectID))
	appendIfRequested([]byte{0xbf, 0x22}, sgp26EUICCInfo2(ciSubjectID))
	if state.RootSMDS != "" {
		appendIfRequested([]byte{0x83}, bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), []byte(state.RootSMDS)))
	}
	appendIfRequested([]byte{0xa8}, ipaCapabilitiesTLV())
	if profiles := profileListTLV(state); profiles != nil {
		appendIfRequested([]byte{0xbf, 0x2d}, profiles)
	}
	if fixture != nil {
		appendIfRequested([]byte{0xa5}, ipaEuiccDataCertificateTLV(5, fixture.EUMCertificate))
		appendIfRequested([]byte{0xa6}, ipaEuiccDataCertificateTLV(6, fixture.EUICCCertificate))
	}
	if len(transactionID) > 0 {
		appendIfRequested([]byte{0x87}, bertlv.NewValue(bertlv.ContextSpecific.Primitive(7), transactionID))
	}
	if len(objects) == 0 {
		objects = append(objects,
			bertlv.NewValue(bertlv.Application.Primitive(26), cloneBytes(eid)),
			sgp26EUICCInfo1(ciSubjectID),
			sgp26EUICCInfo2(ciSubjectID),
			ipaCapabilitiesTLV(),
		)
	}
	return &protocolasn1.IpaEuiccDataResponse{
		Data: &protocolasn1.IpaEuiccData{
			RawObjects: objects,
		},
	}, nil
}

func subjectKeyIDFromFixture(fixture *SGP26Fixture) ([]byte, error) {
	if fixture == nil || len(fixture.CICertificate) == 0 {
		return []byte{0xaa, 0x01}, nil
	}
	return pki.SubjectKeyIdentifier(fixture.CICertificate)
}

func profileListTLV(state *DeviceState) *bertlv.TLV {
	if state == nil || len(state.Profiles) == 0 {
		return nil
	}
	profiles := make([]protocolasn1.ProfileInfo, 0, len(state.Profiles))
	for _, record := range state.Profiles {
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
	list, err := (&protocolasn1.ProfileInfoListResponse{Profiles: profiles}).MarshalBERTLV()
	if err != nil {
		return nil
	}
	return list
}

func tagListContains(tagList, tag []byte) bool {
	if len(tagList) == 0 {
		return true
	}
	for _, entry := range parseTagList(tagList) {
		if bytes.Equal(entry, tag) {
			return true
		}
	}
	return false
}

func parseTagList(tagList []byte) [][]byte {
	if len(tagList) == 0 {
		return nil
	}
	entries := make([][]byte, 0, 8)
	for i := 0; i < len(tagList); {
		n := tagListEntryLength(tagList, i)
		if n <= 0 {
			break
		}
		entries = append(entries, cloneBytes(tagList[i:i+n]))
		i += n
	}
	return entries
}

func tagListEntryLength(tagList []byte, offset int) int {
	if offset >= len(tagList) {
		return 0
	}
	if tagList[offset]&0x1f != 0x1f {
		return 1
	}
	n := 1
	for offset+n < len(tagList) {
		n++
		if tagList[offset+n-1]&0x80 == 0 {
			return n
		}
	}
	return 0
}
