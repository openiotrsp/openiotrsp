package file_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	signingfile "github.com/openiotrsp/openiotrsp/signing/file"
)

func TestSignerSignsAndVerifiesWithEIMPublicKey(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate eIM key: %v", err)
	}
	certDER := makeSelfSignedCertificate(t, key)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "eim-key.pem")
	certPath := filepath.Join(dir, "eim-cert.pem")
	writePEM(t, keyPath, "EC PRIVATE KEY", marshalECPrivateKey(t, key))
	writePEM(t, certPath, "CERTIFICATE", certDER)

	signer, err := signingfile.Load(keyPath, certPath)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}

	payload := []byte("payload to sign as the eIM")
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	publicKey, ok := signer.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", signer.PublicKey())
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		t.Fatalf("signature did not verify with eIM public key")
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	if ecdsa.VerifyASN1(&otherKey.PublicKey, digest[:], signature) {
		t.Fatalf("signature verified with a different public key")
	}

	if got := signer.CertificateDER(); string(got) != string(certDER) {
		t.Fatalf("CertificateDER did not return the loaded eIM certificate")
	}
}

func makeSelfSignedCertificate(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "SGP.26 Test eIM",
			Organization: []string{"RSPTEST"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func marshalECPrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC private key: %v", err)
	}
	return der
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("close %s: %v", path, err)
		}
	}()

	if err := pem.Encode(file, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatalf("write PEM %s: %v", path, err)
	}
}
