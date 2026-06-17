package euiccpkg

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
)

func TestNewEIMConfigurationDataFromCertificateUsesA1Wrapper(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	config, err := NewEIMConfigurationDataFromCertificate("eim.symb-iot.com", "eim.symb-iot.com", 2, testCertificateDER(t, signer))
	if err != nil {
		t.Fatalf("NewEIMConfigurationDataFromCertificate() error = %v", err)
	}
	if err := ValidateInitialEIMConfigurationData(config); err != nil {
		t.Fatalf("ValidateInitialEIMConfigurationData() error = %v", err)
	}
	encoded, err := config.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	a5 := encoded.First(bertlv.ContextSpecific.Constructed(5))
	if a5 == nil || len(a5.Children) != 1 || !a5.Children[0].Tag.Equal(bertlv.ContextSpecific.Constructed(1)) {
		t.Fatalf("eimPublicKeyData = %v, want A5/A1 certificate wrapper", encoded)
	}
}

func TestNewEIMConfigurationDataFromPublicKeyUsesA0Wrapper(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	config, err := NewEIMConfigurationDataFromPublicKey("eim.example", "eim.example", 1, signer.PublicKey())
	if err != nil {
		t.Fatalf("NewEIMConfigurationDataFromPublicKey() error = %v", err)
	}
	encoded, err := config.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	a5 := encoded.First(bertlv.ContextSpecific.Constructed(5))
	if a5 == nil || len(a5.Children) != 1 || !a5.Children[0].Tag.Equal(bertlv.ContextSpecific.Constructed(0)) {
		t.Fatalf("eimPublicKeyData = %v, want A5/A0 SPKI wrapper", encoded)
	}
}

func testCertificateDER(t *testing.T, signer *testSigner) []byte {
	t.Helper()
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
	}, signer.PublicKey(), signer.key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return der
}
