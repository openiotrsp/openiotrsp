package pki_test

import (
	"archive/zip"
	"crypto/x509"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openiotrsp/openiotrsp/pki"
)

const sgp26ZipPath = "../spec/SGP.26_v3.0.2-17-July-2025.zip"

var sgp26VariantONISTPaths = map[string]string{
	"ci":    "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/CI/CERT_CI_SIG_NIST.der",
	"eim":   "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EIM/CERT_S_EIMsign_ECDSA_NIST.der",
	"euicc": "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/CERT_EUICC_SIG_NIST.der",
	"eum":   "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EUM/CERT_EUM_SIG_NIST.der",
}

func TestRealSGP26VariantONISTChains(t *testing.T) {
	t.Parallel()

	certs := loadSGP26VariantONISTCertificates(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	validator, err := pki.NewValidator([][]byte{certs["ci"]}, pki.WithCurrentTime(now))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	for _, name := range []string{"ci", "eim", "euicc", "eum"} {
		assertP256Certificate(t, parseCertificate(t, certs[name]))
	}

	if err := validator.ValidateChain([][]byte{certs["eim"]}); err != nil {
		t.Fatalf("ValidateChain eIM signing certificate: %v", err)
	}

	err = validator.ValidateChain([][]byte{certs["euicc"], certs["eum"]})
	if err == nil {
		t.Fatalf("ValidateChain accepted real eUICC chain despite generic name-constraints handling")
	}
	errText := strings.ToLower(err.Error())
	if !strings.Contains(err.Error(), "2.5.29.30") &&
		!strings.Contains(errText, "name constraint") &&
		!strings.Contains(errText, "unhandled critical extension") {
		t.Fatalf("ValidateChain eUICC error = %q, want name-constraints critical-extension failure", err)
	}

	if err := validator.ValidateEUICCChain([][]byte{certs["euicc"], certs["eum"]}); err != nil {
		t.Fatalf("ValidateEUICCChain real eUICC/EUM chain: %v", err)
	}
	if err := validator.ValidateEUICCChain([][]byte{certs["euicc"], certs["eum"], certs["ci"]}); err != nil {
		t.Fatalf("ValidateEUICCChain real eUICC/EUM/CI chain: %v", err)
	}
}

func TestRealSGP26VariantONISTEUICCChainRejectsBadInputs(t *testing.T) {
	t.Parallel()

	certs := loadSGP26VariantONISTCertificates(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	validator, err := pki.NewValidator([][]byte{certs["ci"]}, pki.WithCurrentTime(now))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	wrongRootValidator, err := pki.NewValidator([][]byte{newTestChain(t, now, "wrong-root").rootDER}, pki.WithCurrentTime(now))
	if err != nil {
		t.Fatalf("new wrong-root validator: %v", err)
	}
	eum := parseCertificate(t, certs["eum"])
	forgedSigner := generateKey(t)
	forgedIssuer := &x509.Certificate{
		SerialNumber:          big.NewInt(45),
		Subject:               eum.Subject,
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	forgedEUICC := makeCertificate(t, certRequest{
		serial:    big.NewInt(44),
		subject:   parseCertificate(t, certs["euicc"]).Subject,
		issuer:    forgedIssuer,
		publicKey: generateKey(t).Public(),
		signerKey: forgedSigner,
		notBefore: now.Add(-24 * time.Hour),
		notAfter:  now.Add(24 * time.Hour),
		isCA:      false,
	})

	tests := []struct {
		name  string
		chain [][]byte
	}{
		{
			name:  "tampered eUICC certificate",
			chain: [][]byte{tamperCertificateSignature(certs["euicc"]), certs["eum"]},
		},
		{
			name:  "tampered EUM certificate",
			chain: [][]byte{certs["euicc"], tamperCertificateSignature(certs["eum"])},
		},
		{
			name:  "truncated chain",
			chain: [][]byte{certs["euicc"]},
		},
		{
			name:  "wrong included CI root",
			chain: [][]byte{certs["euicc"], certs["eum"], newTestChain(t, now, "wrong-root").rootDER},
		},
		{
			name:  "eUICC not signed by EUM",
			chain: [][]byte{forgedEUICC, certs["eum"]},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := validator.ValidateEUICCChain(tt.chain); err == nil {
				t.Fatalf("ValidateEUICCChain accepted invalid real chain")
			}
		})
	}

	if err := wrongRootValidator.ValidateEUICCChain([][]byte{certs["euicc"], certs["eum"]}); err == nil {
		t.Fatalf("ValidateEUICCChain accepted real chain with an untrusted configured root")
	}
}

func loadSGP26VariantONISTCertificates(t *testing.T) map[string][]byte {
	t.Helper()

	if _, err := os.Stat(sgp26ZipPath); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("SGP.26 ZIP not present at %s", sgp26ZipPath)
		}
		t.Fatalf("stat SGP.26 ZIP: %v", err)
	}

	reader, err := zip.OpenReader(sgp26ZipPath)
	if err != nil {
		t.Fatalf("open SGP.26 ZIP: %v", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Fatalf("close SGP.26 ZIP: %v", err)
		}
	}()

	entries := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		entries[file.Name] = file
	}

	certs := make(map[string][]byte, len(sgp26VariantONISTPaths))
	for name, path := range sgp26VariantONISTPaths {
		file := entries[path]
		if file == nil {
			t.Fatalf("SGP.26 ZIP missing %s", path)
		}
		certs[name] = readZipFile(t, file)
	}
	return certs
}

func readZipFile(t *testing.T, file *zip.File) []byte {
	t.Helper()

	reader, err := file.Open()
	if err != nil {
		t.Fatalf("open %s in ZIP: %v", file.Name, err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Fatalf("close %s in ZIP: %v", file.Name, err)
		}
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read %s in ZIP: %v", file.Name, err)
	}
	return data
}
