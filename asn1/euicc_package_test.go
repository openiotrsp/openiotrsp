package asn1

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
)

func TestMarshalX509ChoiceCertificateUsesA1Wrapper(t *testing.T) {
	t.Parallel()

	config := &EimConfigurationData{
		EimID: "eim.symb-iot.com",
		EimPublicKeyData: &X509Choice{
			Kind: X509Certificate,
			Data: mustParseTLV(t, testCertificateDER(t)),
		},
	}
	encoded, err := config.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	a5 := encoded.First(bertlv.ContextSpecific.Constructed(5))
	if a5 == nil {
		t.Fatalf("encoded = %x, missing A5 eimPublicKeyData", mustMarshal(t, encoded))
	}
	if len(a5.Children) != 1 || !a5.Children[0].Tag.Equal(bertlv.ContextSpecific.Constructed(1)) {
		t.Fatalf("eimPublicKeyData CHOICE = %s, want A1 certificate arm", tlvTagPath(a5))
	}
}

func TestMarshalX509ChoicePublicKeyUsesA0Wrapper(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	choice := &X509Choice{
		Kind: X509SubjectPublicKeyInfo,
		Data: mustParseTLV(t, spkiDER),
	}
	encoded, err := marshalX509Choice(bertlv.ContextSpecific.Constructed(5), choice)
	if err != nil {
		t.Fatalf("marshalX509Choice() error = %v", err)
	}
	if len(encoded.Children) != 1 || !encoded.Children[0].Tag.Equal(bertlv.ContextSpecific.Constructed(0)) {
		t.Fatalf("encoded CHOICE arm = %s, want A0", tlvTagPath(encoded))
	}
}

func TestUnmarshalX509ChoiceRejectsBareCertificate(t *testing.T) {
	t.Parallel()

	broken := constructed(bertlv.ContextSpecific.Constructed(5), rawChild(mustParseTLV(t, testCertificateDER(t))))
	var config EimConfigurationData
	if err := config.UnmarshalBERTLV(constructed(tagSequence, broken)); err == nil {
		t.Fatal("UnmarshalBERTLV() error = nil, want missing A1 wrapper error")
	}
}

// TestUnmarshalX509ChoiceAcceptsImplicitAndNestedArms covers both shapes an
// A0/A1 CHOICE arm takes on the wire. Under AUTOMATIC TAGS a strict encoder
// makes the arm tag IMPLICIT, replacing the X.509 SEQUENCE identifier octet so
// the fields sit directly under the arm; this library and others nest the whole
// SEQUENCE instead. Decoding either must yield the same X509Choice, so an
// EimConfigurationData handed to us by a card or another eIM still parses.
func TestUnmarshalX509ChoiceAcceptsImplicitAndNestedArms(t *testing.T) {
	t.Parallel()

	certificate := mustParseTLV(t, testCertificateDER(t))
	publicKey := mustParseTLV(t, testSPKIDER(t))

	tests := []struct {
		name    string
		field   bertlv.Tag
		arm     bertlv.Tag
		object  *bertlv.TLV
		wantKey X509ChoiceKind
	}{
		{
			name:    "eimPublicKeyData certificate",
			field:   bertlv.ContextSpecific.Constructed(5),
			arm:     bertlv.ContextSpecific.Constructed(1),
			object:  certificate,
			wantKey: X509Certificate,
		},
		{
			name:    "trustedPublicKeyDataTls SubjectPublicKeyInfo",
			field:   bertlv.ContextSpecific.Constructed(6),
			arm:     bertlv.ContextSpecific.Constructed(0),
			object:  publicKey,
			wantKey: X509SubjectPublicKeyInfo,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			nested := constructed(test.field, constructed(test.arm, rawChild(test.object)))
			// IMPLICIT: the arm tag replaces the SEQUENCE identifier octet.
			implicit := constructed(test.field, constructed(test.arm, test.object.Children...))
			if len(implicit.Children[0].Children) < 2 {
				t.Fatalf("IMPLICIT arm has %d fields, too few to distinguish from a nested SEQUENCE", len(implicit.Children[0].Children))
			}

			eimID := bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte("eim.symb-iot.com"))
			var fromNested, fromImplicit EimConfigurationData
			if err := fromNested.UnmarshalBERTLV(constructed(tagSequence, eimID, nested)); err != nil {
				t.Fatalf("UnmarshalBERTLV(nested) error = %v", err)
			}
			if err := fromImplicit.UnmarshalBERTLV(constructed(tagSequence, eimID, implicit)); err != nil {
				t.Fatalf("UnmarshalBERTLV(IMPLICIT) error = %v", err)
			}

			for label, decoded := range map[string]EimConfigurationData{"nested": fromNested, "IMPLICIT": fromImplicit} {
				choice := decoded.EimPublicKeyData
				if choice == nil {
					choice = decoded.TrustedPublicKeyDataTLS
				}
				if choice == nil {
					t.Fatalf("%s: no X.509 choice decoded", label)
				}
				if choice.Kind != test.wantKey {
					t.Fatalf("%s: kind = %d, want %d", label, choice.Kind, test.wantKey)
				}
				if got, want := mustMarshal(t, choice.Data), mustMarshal(t, test.object); !bytes.Equal(got, want) {
					t.Fatalf("%s: X.509 object = %x, want %x", label, got, want)
				}
			}
		})
	}
}

func TestUnmarshalX509ChoiceRejectsEmptyArm(t *testing.T) {
	t.Parallel()

	eimID := bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte("eim.symb-iot.com"))
	empty := constructed(bertlv.ContextSpecific.Constructed(5), constructed(bertlv.ContextSpecific.Constructed(1)))
	var config EimConfigurationData
	if err := config.UnmarshalBERTLV(constructed(tagSequence, eimID, empty)); err == nil {
		t.Fatal("UnmarshalBERTLV() error = nil, want empty CHOICE arm error")
	}
}

func TestEimConfigurationDataX509ChoiceRoundTrip(t *testing.T) {
	t.Parallel()

	config := &EimConfigurationData{
		EimID:        "eim.symb-iot.com",
		EimFQDN:      stringPtr("eim.symb-iot.com"),
		CounterValue: int64Ptr(2),
		EimPublicKeyData: &X509Choice{
			Kind: X509Certificate,
			Data: mustParseTLV(t, testCertificateDER(t)),
		},
	}
	encoded, err := config.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	var decoded EimConfigurationData
	if err := decoded.UnmarshalBERTLV(encoded); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if decoded.EimPublicKeyData == nil || decoded.EimPublicKeyData.Kind != X509Certificate {
		t.Fatalf("decoded kind = %#v, want X509Certificate", decoded.EimPublicKeyData)
	}
	reencoded, err := decoded.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV(round-trip) error = %v", err)
	}
	if !bytes.Equal(mustMarshal(t, encoded), mustMarshal(t, reencoded)) {
		t.Fatalf("round-trip DER mismatch:\n got %x\nwant %x", mustMarshal(t, reencoded), mustMarshal(t, encoded))
	}
}

func TestTrustedPublicKeyDataTLSUsesSameChoiceWrapper(t *testing.T) {
	t.Parallel()

	config := &EimConfigurationData{
		EimID: "eim.example",
		TrustedPublicKeyDataTLS: &X509Choice{
			Kind: X509Certificate,
			Data: mustParseTLV(t, testCertificateDER(t)),
		},
	}
	encoded, err := config.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	a6 := encoded.First(bertlv.ContextSpecific.Constructed(6))
	if a6 == nil || len(a6.Children) != 1 || !a6.Children[0].Tag.Equal(bertlv.ContextSpecific.Constructed(1)) {
		t.Fatalf("trustedPublicKeyDataTLS = %s, want A6/A1 certificate arm", tlvTagPath(encoded))
	}
}

func testCertificateDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "eim.symb-iot.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test EIM CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return der
}

func testSPKIDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return der
}

func int64Ptr(value int64) *int64 {
	return &value
}

func mustParseTLV(t *testing.T, der []byte) *bertlv.TLV {
	t.Helper()
	tlv, err := parseTLV(der)
	if err != nil {
		t.Fatalf("parseTLV() error = %v", err)
	}
	return tlv
}

func mustMarshal(t *testing.T, tlv *bertlv.TLV) []byte {
	t.Helper()
	raw, err := tlv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return raw
}

func tlvTagPath(tlv *bertlv.TLV) string {
	if tlv == nil {
		return "<nil>"
	}
	if len(tlv.Children) == 0 {
		return tlv.Tag.String()
	}
	out := tlv.Tag.String() + "{"
	for i, child := range tlv.Children {
		if i > 0 {
			out += ","
		}
		out += tlvTagPath(child)
	}
	return out + "}"
}
