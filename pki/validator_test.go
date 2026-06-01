package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openiotrsp/openiotrsp/pki"
)

func TestValidateChainRejectsInvalidChains(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	good := newTestChain(t, now, "primary")
	wrongRoot := newTestChain(t, now, "wrong-root")
	swappedIntermediate := makeCertificate(t, certRequest{
		serial:    big.NewInt(43),
		subject:   good.intermediateSubject,
		issuer:    good.rootCert,
		publicKey: generateKey(t).Public(),
		signerKey: good.rootKey,
		notBefore: now.Add(-24 * time.Hour),
		notAfter:  now.Add(24 * time.Hour),
		isCA:      true,
	})
	expired := newTestChain(t, now, "expired")
	expired.leafDER = makeCertificate(t, certRequest{
		serial:    big.NewInt(42),
		subject:   expired.leafSubject,
		issuer:    expired.intermediateCert,
		publicKey: expired.leafKey.Public(),
		signerKey: expired.intermediateKey,
		notBefore: now.Add(-48 * time.Hour),
		notAfter:  now.Add(-24 * time.Hour),
		isCA:      false,
	})

	validator, err := pki.NewValidator([][]byte{good.rootDER}, pki.WithCurrentTime(now))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	tests := []struct {
		name    string
		chain   [][]byte
		wantErr string
	}{
		{
			name:    "wrong CA root",
			chain:   [][]byte{wrongRoot.leafDER, wrongRoot.intermediateDER},
			wantErr: "unknown authority",
		},
		{
			name:    "tampered signature",
			chain:   [][]byte{tamperCertificateSignature(good.leafDER), good.intermediateDER},
			wantErr: "ECDSA verification failure",
		},
		{
			name:    "expired certificate",
			chain:   [][]byte{expired.leafDER, expired.intermediateDER},
			wantErr: "expired",
		},
		{
			name:    "truncated chain",
			chain:   [][]byte{good.leafDER},
			wantErr: "unknown authority",
		},
		{
			name:    "swapped intermediate",
			chain:   [][]byte{good.leafDER, swappedIntermediate},
			wantErr: "ECDSA verification failure",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validator.ValidateChain(tt.chain)
			if err == nil {
				t.Fatalf("ValidateChain succeeded for invalid chain")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateChain error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateChainAcceptsSGP26StyleP256Chain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	chain := newTestChain(t, now, "prime256v1")
	validator, err := pki.NewValidator([][]byte{chain.rootDER}, pki.WithCurrentTime(now))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	assertP256Certificate(t, chain.rootCert)
	assertP256Certificate(t, chain.intermediateCert)
	assertP256Certificate(t, parseCertificate(t, chain.leafDER))

	if err := validator.ValidateChain([][]byte{chain.leafDER, chain.intermediateDER}); err != nil {
		t.Fatalf("ValidateChain leaf/intermediate: %v", err)
	}
	if err := validator.ValidateChain([][]byte{chain.leafDER, chain.intermediateDER, chain.rootDER}); err != nil {
		t.Fatalf("ValidateChain leaf/intermediate/root: %v", err)
	}
}

type testChain struct {
	rootDER             []byte
	intermediateDER     []byte
	leafDER             []byte
	rootCert            *x509.Certificate
	intermediateCert    *x509.Certificate
	rootKey             *ecdsa.PrivateKey
	intermediateKey     *ecdsa.PrivateKey
	leafKey             *ecdsa.PrivateKey
	intermediateSubject pkix.Name
	leafSubject         pkix.Name
}

type certRequest struct {
	serial    *big.Int
	subject   pkix.Name
	issuer    *x509.Certificate
	publicKey any
	signerKey *ecdsa.PrivateKey
	notBefore time.Time
	notAfter  time.Time
	isCA      bool
}

func newTestChain(t *testing.T, now time.Time, suffix string) testChain {
	t.Helper()

	rootKey := generateKey(t)
	intermediateKey := generateKey(t)
	leafKey := generateKey(t)

	rootSubject := pkix.Name{
		Country:            []string{"IT"},
		Organization:       []string{"RSPTEST"},
		OrganizationalUnit: []string{"TESTCERT"},
		CommonName:         "GSMA SGP.26 Test CI " + suffix,
	}
	intermediateSubject := pkix.Name{
		Country:            []string{"IT"},
		Organization:       []string{"RSPTEST"},
		OrganizationalUnit: []string{"TESTCERT"},
		CommonName:         "SGP.26 Test SM-DP+ " + suffix,
	}
	leafSubject := pkix.Name{
		Country:            []string{"IT"},
		Organization:       []string{"RSPTEST"},
		OrganizationalUnit: []string{"TESTCERT"},
		CommonName:         "SGP.26 Test eUICC " + suffix,
	}

	rootDER := makeCertificate(t, certRequest{
		serial:    big.NewInt(1),
		subject:   rootSubject,
		publicKey: rootKey.Public(),
		signerKey: rootKey,
		notBefore: now.Add(-24 * time.Hour),
		notAfter:  now.Add(24 * time.Hour),
		isCA:      true,
	})
	rootCert := parseCertificate(t, rootDER)

	intermediateDER := makeCertificate(t, certRequest{
		serial:    big.NewInt(2),
		subject:   intermediateSubject,
		issuer:    rootCert,
		publicKey: intermediateKey.Public(),
		signerKey: rootKey,
		notBefore: now.Add(-24 * time.Hour),
		notAfter:  now.Add(24 * time.Hour),
		isCA:      true,
	})
	intermediateCert := parseCertificate(t, intermediateDER)

	leafDER := makeCertificate(t, certRequest{
		serial:    big.NewInt(3),
		subject:   leafSubject,
		issuer:    intermediateCert,
		publicKey: leafKey.Public(),
		signerKey: intermediateKey,
		notBefore: now.Add(-24 * time.Hour),
		notAfter:  now.Add(24 * time.Hour),
		isCA:      false,
	})

	return testChain{
		rootDER:             rootDER,
		intermediateDER:     intermediateDER,
		leafDER:             leafDER,
		rootCert:            rootCert,
		intermediateCert:    intermediateCert,
		rootKey:             rootKey,
		intermediateKey:     intermediateKey,
		leafKey:             leafKey,
		intermediateSubject: intermediateSubject,
		leafSubject:         leafSubject,
	}
}

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func makeCertificate(t *testing.T, req certRequest) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          req.serial,
		Subject:               req.subject,
		NotBefore:             req.notBefore,
		NotAfter:              req.notAfter,
		BasicConstraintsValid: true,
		IsCA:                  req.isCA,
	}
	if req.isCA {
		template.KeyUsage = x509.KeyUsageCertSign
		template.MaxPathLen = 1
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	issuer := req.issuer
	if issuer == nil {
		issuer = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, req.publicKey, req.signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func parseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func assertP256Certificate(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if publicKey.Curve != elliptic.P256() {
		t.Fatalf("certificate curve = %q, want prime256v1/P-256", publicKey.Curve.Params().Name)
	}
}

func tamperCertificateSignature(der []byte) []byte {
	var cert testCertificate
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		panic(err)
	}
	cert.SignatureValue.Bytes[len(cert.SignatureValue.Bytes)-1] ^= 0x01

	tampered, err := asn1.Marshal(cert)
	if err != nil {
		panic(err)
	}
	return tampered
}

type testCertificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}
