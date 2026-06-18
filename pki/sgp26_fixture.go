package pki

import (
	"path/filepath"
	"archive/zip"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

const (
	DefaultSGP26Zip = "spec/SGP.26_v3.0.2-17-July-2025.zip"
	// DefaultSGP26Dir is the committed Variant O NIST test PKI used when the GSMA zip is absent.
	DefaultSGP26Dir = "testdata/sgp26_variant_o"
)

var sgp26VariantONISTFileNames = struct {
	CI, EUM, EUICC, EUICCKey, EIMCert, EIMKey string
}{
	CI:       "CERT_CI_SIG_NIST.der",
	EUM:      "CERT_EUM_SIG_NIST.der",
	EUICC:    "CERT_EUICC_SIG_NIST.der",
	EUICCKey: "SK_EUICC_SIG_NIST.pem",
	EIMCert:  "CERT_S_EIMsign_ECDSA_NIST.der",
	EIMKey:   "SK_S_EIMsign_ECDSA_NIST.pem",
}

var sgp26VariantONISTPaths = struct {
	CI, EUM, EUICC, EUICCKey, EIMCert, EIMKey string
}{
	CI:       "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/CI/CERT_CI_SIG_NIST.der",
	EUM:      "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EUM/CERT_EUM_SIG_NIST.der",
	EUICC:    "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/CERT_EUICC_SIG_NIST.der",
	EUICCKey: "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/SK_EUICC_SIG_NIST.pem",
	EIMCert:  "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EIM/CERT_S_EIMsign_ECDSA_NIST.der",
	EIMKey:   "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EIM/SK_S_EIMsign_ECDSA_NIST.pem",
}

// SGP26VariantONISTMaterial is the Variant O NIST test PKI used by mock IPA demos.
type SGP26VariantONISTMaterial struct {
	CICertificate    []byte
	EUMCertificate   []byte
	EUICCCertificate []byte
	EIMCertificate   []byte
	EUICCKey         *ecdsa.PrivateKey
	EIMKey           *ecdsa.PrivateKey
	EID              string
}

// ResolveFixturePath finds a readable path for a repo-relative fixture file.
func ResolveFixturePath(path string) (string, error) {
	candidates := []string{path, "../" + path, "../../" + path}
	var lastErr error
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else {
			lastErr = err
		}
	}
	return "", fmt.Errorf("pki: fixture unavailable at %s: %w", path, lastErr)
}

// LoadSGP26VariantONISTMaterial loads CI/EUM/eUICC/eIM test material from the
// committed testdata directory or, when present, the GSMA zip.
func LoadSGP26VariantONISTMaterial(zipPath string) (*SGP26VariantONISTMaterial, error) {
	if material, err := loadSGP26VariantONISTFromDir(DefaultSGP26Dir); err == nil {
		return material, nil
	}
	return loadSGP26VariantONISTFromZip(zipPath)
}

func loadSGP26VariantONISTFromDir(dir string) (*SGP26VariantONISTMaterial, error) {
	resolvedDir, err := ResolveFixturePath(dir)
	if err != nil {
		return nil, err
	}
	readFile := func(name string) ([]byte, error) {
		data, err := os.ReadFile(filepath.Join(resolvedDir, name))
		if err != nil {
			return nil, fmt.Errorf("pki: read SGP.26 fixture %s: %w", name, err)
		}
		return data, nil
	}
	return assembleSGP26VariantONISTMaterial(readFile)
}

func loadSGP26VariantONISTFromZip(zipPath string) (*SGP26VariantONISTMaterial, error) {
	if zipPath == "" {
		zipPath = DefaultSGP26Zip
	}
	resolvedPath, err := ResolveFixturePath(zipPath)
	if err != nil {
		return nil, err
	}
	reader, err := zip.OpenReader(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("pki: open SGP.26 fixture zip: %w", err)
	}
	defer func() {
		_ = reader.Close()
	}()
	files := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		files[file.Name] = file
	}
	readEntry := func(zipPath string) ([]byte, error) {
		file := files[zipPath]
		if file == nil {
			return nil, fmt.Errorf("pki: SGP.26 fixture missing %s", zipPath)
		}
		return readZipEntry(file)
	}
	return assembleSGP26VariantONISTMaterial(func(name string) ([]byte, error) {
		switch name {
		case sgp26VariantONISTFileNames.CI:
			return readEntry(sgp26VariantONISTPaths.CI)
		case sgp26VariantONISTFileNames.EUM:
			return readEntry(sgp26VariantONISTPaths.EUM)
		case sgp26VariantONISTFileNames.EUICC:
			return readEntry(sgp26VariantONISTPaths.EUICC)
		case sgp26VariantONISTFileNames.EUICCKey:
			return readEntry(sgp26VariantONISTPaths.EUICCKey)
		case sgp26VariantONISTFileNames.EIMCert:
			return readEntry(sgp26VariantONISTPaths.EIMCert)
		case sgp26VariantONISTFileNames.EIMKey:
			return readEntry(sgp26VariantONISTPaths.EIMKey)
		default:
			return nil, fmt.Errorf("pki: unknown SGP.26 fixture file %s", name)
		}
	})
}

func assembleSGP26VariantONISTMaterial(readFile func(string) ([]byte, error)) (*SGP26VariantONISTMaterial, error) {
	ci, err := readFile(sgp26VariantONISTFileNames.CI)
	if err != nil {
		return nil, err
	}
	eum, err := readFile(sgp26VariantONISTFileNames.EUM)
	if err != nil {
		return nil, err
	}
	euicc, err := readFile(sgp26VariantONISTFileNames.EUICC)
	if err != nil {
		return nil, err
	}
	euiccKeyPEM, err := readFile(sgp26VariantONISTFileNames.EUICCKey)
	if err != nil {
		return nil, err
	}
	euiccKey, err := ParseECDSAPrivateKeyPEM(euiccKeyPEM)
	if err != nil {
		return nil, err
	}
	eid, err := EIDHexFromCertificate(euicc)
	if err != nil {
		return nil, err
	}
	material := &SGP26VariantONISTMaterial{
		CICertificate:    ci,
		EUMCertificate:   eum,
		EUICCCertificate: euicc,
		EUICCKey:         euiccKey,
		EID:              eid,
	}
	if eimCert, err := readFile(sgp26VariantONISTFileNames.EIMCert); err == nil {
		material.EIMCertificate = eimCert
	}
	if eimKeyPEM, err := readFile(sgp26VariantONISTFileNames.EIMKey); err == nil {
		if key, err := ParseECDSAPrivateKeyPEM(eimKeyPEM); err == nil {
			material.EIMKey = key
		}
	}
	return material, nil
}

// ParseECDSAPrivateKeyPEM parses an ECDSA private key from PEM bytes.
func ParseECDSAPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		pemBytes = rest
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if ok {
			return ecdsaKey, nil
		}
	}
	return nil, fmt.Errorf("pki: parse ECDSA private key PEM")
}

func readZipEntry(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("pki: open %s in SGP.26 fixture: %w", file.Name, err)
	}
	defer func() {
		_ = reader.Close()
	}()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("pki: read %s in SGP.26 fixture: %w", file.Name, err)
	}
	return data, nil
}
