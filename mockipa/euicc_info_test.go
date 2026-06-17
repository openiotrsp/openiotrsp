package mockipa

import (
	"encoding/hex"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/openiotrsp/openiotrsp/pki"
)

func TestSGP26EUICCInfo2UsesUniversalPPVersionAndSASFields(t *testing.T) {
	t.Parallel()

	fixture := requireSGP26SoftwareFixture(t)
	ciSubjectKeyID, err := pki.SubjectKeyIdentifier(fixture.CICertificate)
	if err != nil {
		t.Fatalf("SubjectKeyIdentifier() error = %v", err)
	}
	info2 := sgp26EUICCInfo2(ciSubjectKeyID)
	if info2.First(bertlv.ContextSpecific.Primitive(22)) != nil {
		t.Fatal("EUICCInfo2 must not encode ppVersion with context tag 22")
	}
	if info2.First(bertlv.ContextSpecific.Primitive(23)) != nil {
		t.Fatal("EUICCInfo2 must not encode sasAcreditationNumber with context tag 23")
	}
	ppVersion := info2.First(bertlv.Universal.Primitive(4))
	if ppVersion == nil || hex.EncodeToString(ppVersion.Value) != "ffffff" {
		t.Fatalf("ppVersion = %v, want universal OCTET STRING ffffff", ppVersion)
	}
	sas := info2.First(bertlv.Universal.Primitive(12))
	if sas == nil {
		t.Fatal("sasAcreditationNumber missing universal UTF8String tag")
	}
}

func TestAuthenticateResponseOkUsesChoiceArmZero(t *testing.T) {
	t.Parallel()

	euiccSigned1 := bertlv.NewChildren(bertlv.Universal.Constructed(16),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x01}),
	)
	response := authenticateResponseOkTLV(
		euiccSigned1,
		[]byte{0x30},
		[]byte{0x30, 0x03, 0x02, 0x01, 0x00},
		[]byte{0x30, 0x03, 0x02, 0x01, 0x01},
	)
	choice := response.First(bertlv.ContextSpecific.Constructed(0))
	if choice == nil {
		t.Fatalf("response = %#v, want authenticateResponseOk choice arm A0", response)
	}
	if choice.First(bertlv.Universal.Constructed(16)) == nil {
		t.Fatal("authenticateResponseOk choice arm missing euiccSigned1")
	}
	if response.First(bertlv.Universal.Constructed(16)) != nil {
		t.Fatal("authenticateServerResponse must not wrap authenticateResponseOk in an extra universal SEQUENCE")
	}
}

func TestPrepareDownloadResponseOkUsesChoiceArmZero(t *testing.T) {
	t.Parallel()

	euiccSigned2 := bertlv.NewChildren(bertlv.Universal.Constructed(16),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x01}),
	)
	response := prepareDownloadResponseOkTLV(euiccSigned2, []byte{0x30})
	choice := response.First(bertlv.ContextSpecific.Constructed(0))
	if choice == nil {
		t.Fatalf("response = %#v, want downloadResponseOk choice arm A0", response)
	}
	if choice.First(bertlv.Universal.Constructed(16)) == nil {
		t.Fatal("downloadResponseOk choice arm missing euiccSigned2")
	}
	if response.First(bertlv.Universal.Constructed(16)) != nil {
		t.Fatal("prepareDownloadResponse must not wrap downloadResponseOk in an extra universal SEQUENCE")
	}
}
