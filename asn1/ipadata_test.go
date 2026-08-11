package asn1

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
)

func TestIpaEuiccDataResponseUnwrapsSuccessChoice(t *testing.T) {
	t.Parallel()

	eid := bytes.Repeat([]byte{0x11}, 16)
	bare := constructed(tagIpaEuiccData,
		octetTLV(tagEID, eid),
		constructed(tagEUICCInfo1,
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x03, 0x02, 0x01}),
		),
	)
	choice := constructed(tagIpaEuiccData,
		constructed(bertlv.ContextSpecific.Constructed(0), bare.Children...),
	)

	var decoded IpaEuiccDataResponse
	if err := decoded.UnmarshalBERTLV(choice); err != nil {
		t.Fatalf("UnmarshalBERTLV(CHOICE) error = %v", err)
	}
	if decoded.Data == nil || !bytes.Equal(decoded.Data.EID, eid) {
		t.Fatalf("Data = %#v, want EID %x", decoded.Data, eid)
	}
	if decoded.Data.EUICCInfo1Raw == nil {
		t.Fatal("EUICCInfo1Raw = nil, want BF20")
	}
}

func TestIpaEuiccDataResponseKeepsBareNotificationsList(t *testing.T) {
	t.Parallel()

	// Bare BF52 with only notificationsList [0] must not be mistaken for CHOICE [0].
	// Use UNIVERSAL 16 as a PendingNotification stand-in (accepted by the list decoder).
	notification := constructed(tagSequence, octetTLV(tagEID, bytes.Repeat([]byte{0x22}, 16)))
	bare := constructed(tagIpaEuiccData,
		constructed(bertlv.ContextSpecific.Constructed(0), notification),
	)

	var decoded IpaEuiccDataResponse
	if err := decoded.UnmarshalBERTLV(bare); err != nil {
		t.Fatalf("UnmarshalBERTLV(bare notifications) error = %v", err)
	}
	if decoded.Data == nil || decoded.Data.NotificationsRaw == nil {
		t.Fatalf("Data = %#v, want notificationsList", decoded.Data)
	}
	if len(decoded.Data.Notifications) != 1 {
		t.Fatalf("notifications = %d, want 1", len(decoded.Data.Notifications))
	}
}

func TestIpaEuiccDataResponseUnwrapsErrorChoice(t *testing.T) {
	t.Parallel()

	code, err := integerTLV(tagInteger, IpaEuiccDataErrorCode(127))
	if err != nil {
		t.Fatalf("integerTLV() error = %v", err)
	}
	choice := constructed(tagIpaEuiccData,
		constructed(bertlv.ContextSpecific.Constructed(1),
			octetTLV(bertlv.ContextSpecific.Primitive(0), []byte{0x01, 0x02}),
			code,
		),
	)

	var decoded IpaEuiccDataResponse
	if err := decoded.UnmarshalBERTLV(choice); err != nil {
		t.Fatalf("UnmarshalBERTLV(error CHOICE) error = %v", err)
	}
	if decoded.Error == nil || decoded.Error.Code != 127 {
		t.Fatalf("Error = %#v, want code 127", decoded.Error)
	}
	if !bytes.Equal(decoded.Error.EimTransactionID, []byte{0x01, 0x02}) {
		t.Fatalf("EimTransactionID = %x", decoded.Error.EimTransactionID)
	}
}

func TestCertificateDERFromTaggedAcceptsSiblingFields(t *testing.T) {
	t.Parallel()

	der := testEUICCCertDER(t, "89044045930000000000002153893210")
	certTLV := mustParseCertTLVForTest(t, der)
	if len(certTLV.Children) != 3 {
		t.Fatalf("Certificate children = %d, want 3", len(certTLV.Children))
	}

	// One SEQUENCE child (fixtures/mocks).
	wrapped := constructed(bertlv.ContextSpecific.Constructed(6), certTLV)
	got, err := CertificateDERFromTagged(wrapped)
	if err != nil {
		t.Fatalf("CertificateDERFromTagged(SEQUENCE child) error = %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatalf("DER mismatch for SEQUENCE child shape")
	}

	// Three IMPLICIT siblings under A6 (production).
	implicit := constructed(bertlv.ContextSpecific.Constructed(6), certTLV.Children...)
	got, err = CertificateDERFromTagged(implicit)
	if err != nil {
		t.Fatalf("CertificateDERFromTagged(siblings) error = %v", err)
	}
	parsed, err := x509.ParseCertificate(got)
	if err != nil {
		t.Fatalf("ParseCertificate(siblings DER) error = %v", err)
	}
	if parsed.Subject.SerialNumber != "89044045930000000000002153893210" {
		t.Fatalf("serialNumber = %q", parsed.Subject.SerialNumber)
	}
}

func TestIpaEuiccDataResponseChoiceAndImplicitCertificateFixture(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "testdata", "bf52_ipa_euicc_data_response_choice.der"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	var decoded IpaEuiccDataResponse
	if err := decoded.UnmarshalBERTLV(tlv); err != nil {
		t.Fatalf("UnmarshalBERTLV(CHOICE fixture) error = %v", err)
	}
	if decoded.Data == nil {
		t.Fatal("Data = nil, want success IpaEuiccData")
	}
	if decoded.Data.EUICCInfo1Raw == nil {
		t.Fatal("want EUICCInfo1")
	}
	if decoded.Data.EUICCCertificateRaw == nil {
		t.Fatal("want A6 certificate")
	}
	if len(decoded.Data.EUICCCertificateRaw.Children) != 3 {
		t.Fatalf("A6 children = %d, want 3 IMPLICIT Certificate fields", len(decoded.Data.EUICCCertificateRaw.Children))
	}

	der, err := CertificateDERFromTagged(decoded.Data.EUICCCertificateRaw)
	if err != nil {
		t.Fatalf("CertificateDERFromTagged(A6) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(A6) error = %v", err)
	}
	wantEID := "89044045930000000000002153893210"
	if cert.Subject.SerialNumber != wantEID {
		t.Fatalf("eUICC serialNumber = %q, want %q", cert.Subject.SerialNumber, wantEID)
	}
}

func testEUICCCertDER(t *testing.T, eidHex string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{SerialNumber: eidHex},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	if _, err := hex.DecodeString(eidHex); err != nil {
		t.Fatalf("eidHex: %v", err)
	}
	return der
}

func mustParseCertTLVForTest(t *testing.T, der []byte) *bertlv.TLV {
	t.Helper()
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(der); err != nil {
		t.Fatalf("parse certificate TLV: %v", err)
	}
	return tlv
}
