package mockipa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	sgp22 "github.com/damonto/euicc-go/v2"
	"github.com/openiotrsp/openiotrsp/pki"
)

func TestLoadBoundProfilePackageReturnsSignedProfileInstallationResult(t *testing.T) {
	t.Parallel()

	fixture := testSoftwareEUICCFixture(t)
	euicc, err := NewSoftwareEUICC(fixture)
	if err != nil {
		t.Fatalf("NewSoftwareEUICC() error = %v", err)
	}
	euicc.transaction = []byte{0x01, 0x02, 0x03}
	bpp := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(54),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(35)),
	)
	metadata := &sgp22.ProfileInfo{
		ICCID:   []byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1},
		ISDPAID: []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10},
	}

	response, notification, err := euicc.LoadBoundProfilePackage(
		bpp,
		metadata,
		"smdpp.test.rsp.sysmocom.de",
		stdasn1.ObjectIdentifier{1, 2, 826, 0, 1},
	)
	if err != nil {
		t.Fatalf("LoadBoundProfilePackage() error = %v", err)
	}
	if response.Notification == nil || response.Notification.Address != "smdpp.test.rsp.sysmocom.de" {
		t.Fatalf("notification = %#v, want sysmocom address", response.Notification)
	}
	if notification == nil || notification.PendingNotification == nil {
		t.Fatalf("pending notification = %#v, want signed PIR", notification)
	}
	if euicc.BoundProfilePackage() == nil {
		t.Fatal("BoundProfilePackage() is nil, want captured BPP")
	}

	pir := euicc.ProfileInstallationResult()
	if pir == nil {
		t.Fatal("ProfileInstallationResult() is nil")
	}
	data := pir.First(bertlv.ContextSpecific.Constructed(39))
	signature := pir.First(bertlv.Application.Primitive(55))
	if data == nil || signature == nil {
		t.Fatalf("PIR = %#v, want data and signature", pir)
	}
	if data.First(bertlv.Universal.Primitive(6)) == nil {
		t.Fatal("PIR data missing SM-DP+ OID")
	}
	encoded, err := data.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	digest := sha256.Sum256(encoded)
	ok, err := pki.VerifyECDSATR03111(&fixture.EUICCKey.PublicKey, digest[:], signature.Value)
	if err != nil {
		t.Fatalf("VerifyECDSATR03111() error = %v", err)
	}
	if !ok {
		t.Fatal("PIR signature does not verify with eUICC public key")
	}
}

func testSoftwareEUICCFixture(t *testing.T) *SGP26Fixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CI"},
		SubjectKeyId:          []byte{0xaa, 0xbb, 0xcc},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return &SGP26Fixture{
		CICertificate: certDER,
		EUICCKey:      key,
	}
}
