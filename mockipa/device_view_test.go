package mockipa

import (
	"encoding/hex"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

func TestBuildIpaEuiccDataResponseWrapsCertificatesInA5A6(t *testing.T) {
	t.Parallel()

	fixture := requireSGP26SoftwareFixture(t)
	eid, err := hex.DecodeString(fixture.EID)
	if err != nil {
		t.Fatalf("DecodeString(EID) error = %v", err)
	}
	response, err := buildIpaEuiccDataResponse(eid, fixture, newDeviceState(), &protocolasn1.IpaEuiccDataRequest{
		TagList: []byte{0xa5, 0xa6},
	})
	if err != nil {
		t.Fatalf("buildIpaEuiccDataResponse() error = %v", err)
	}
	if response == nil || response.Data == nil {
		t.Fatal("response data is nil")
	}
	var decoded protocolasn1.IpaEuiccDataResponse
	if err := decoded.UnmarshalBERTLV(mustMarshalIpaEuiccDataResponse(t, response)); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if decoded.Data == nil {
		t.Fatal("decoded data is nil")
	}
	data := decoded.Data
	if data.EUMCertificateRaw == nil || !data.EUMCertificateRaw.Tag.Equal(bertlv.ContextSpecific.Constructed(5)) {
		t.Fatalf("EUM certificate tag = %v, want A5", data.EUMCertificateRaw)
	}
	if data.EUICCCertificateRaw == nil || !data.EUICCCertificateRaw.Tag.Equal(bertlv.ContextSpecific.Constructed(6)) {
		t.Fatalf("eUICC certificate tag = %v, want A6", data.EUICCCertificateRaw)
	}
	if len(data.EUMCertificateRaw.Children) != 1 || len(data.EUICCCertificateRaw.Children) != 1 {
		t.Fatalf("certificate wrappers = %#v / %#v, want one child each", data.EUMCertificateRaw, data.EUICCCertificateRaw)
	}
}

func mustMarshalIpaEuiccDataResponse(t *testing.T, response *protocolasn1.IpaEuiccDataResponse) *bertlv.TLV {
	t.Helper()
	tlv, err := response.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	return tlv
}

func TestTagListContainsParsesMultiByteTags(t *testing.T) {
	t.Parallel()

	tagList := []byte{0xbf, 0x20, 0xbf, 0x22, 0xbf, 0x2d, 0xa5, 0xa6, 0xa8}
	if !tagListContains(tagList, []byte{0xbf, 0x2d}) {
		t.Fatal("tagListContains(BF2D) = false, want true")
	}
	if tagListContains(tagList, []byte{0x2d}) {
		t.Fatal("tagListContains(2D) = true, want false")
	}
}
