package mockipa

import (
	"archive/zip"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/openiotrsp/openiotrsp/pki"
)

const defaultSGP26Zip = "spec/SGP.26_v3.0.2-17-July-2025.zip"

var requiredSGP26FixtureEntries = []string{
	"SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/CI/CERT_CI_SIG_NIST.der",
	"SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/CERT_EUICC_SIG_NIST.der",
	"SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EUM/CERT_EUM_SIG_NIST.der",
	"SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/SK_EUICC_SIG_NIST.pem",
}

// SGP26Fixture contains the material needed by the software eUICC.
type SGP26Fixture struct {
	CICertificate    []byte
	EUICCCertificate []byte
	EUMCertificate   []byte
	EUICCKey         *ecdsa.PrivateKey
	EID              string
}

// ValidateSGP26SoftwareFixture verifies the local material needed to build a
// software SGP.26 test eUICC. It deliberately does not claim a signed-flow pass.
func ValidateSGP26SoftwareFixture(path string) error {
	_, err := LoadSGP26SoftwareFixture(path)
	return err
}

// LoadSGP26SoftwareFixture loads the SGP.26 Variant O NIST software eUICC material.
func LoadSGP26SoftwareFixture(path string) (*SGP26Fixture, error) {
	if path == "" {
		path = defaultSGP26Zip
	}
	resolvedPath, err := resolveFixturePath(path)
	if err != nil {
		return nil, err
	}
	reader, err := zip.OpenReader(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("mockipa: open SGP.26 fixture zip: %w", err)
	}
	defer func() {
		_ = reader.Close()
	}()
	entries := make(map[string]bool, len(reader.File))
	files := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		entries[file.Name] = true
		files[file.Name] = file
	}
	for _, want := range requiredSGP26FixtureEntries {
		if !entries[want] {
			return nil, fmt.Errorf("mockipa: SGP.26 fixture missing %s", want)
		}
	}
	euiccKeyPEM, err := readZipFile(files[requiredSGP26FixtureEntries[3]])
	if err != nil {
		return nil, err
	}
	key, err := parseECDSAPrivateKey(euiccKeyPEM)
	if err != nil {
		return nil, err
	}
	ci, err := readZipFile(files[requiredSGP26FixtureEntries[0]])
	if err != nil {
		return nil, err
	}
	euicc, err := readZipFile(files[requiredSGP26FixtureEntries[1]])
	if err != nil {
		return nil, err
	}
	eum, err := readZipFile(files[requiredSGP26FixtureEntries[2]])
	if err != nil {
		return nil, err
	}
	eid, err := pki.EIDHexFromCertificate(euicc)
	if err != nil {
		return nil, err
	}
	return &SGP26Fixture{
		CICertificate:    ci,
		EUICCCertificate: euicc,
		EUMCertificate:   eum,
		EUICCKey:         key,
		EID:              eid,
	}, nil
}

func resolveFixturePath(path string) (string, error) {
	candidates := []string{path, "../" + path, "../../" + path}
	var lastErr error
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else {
			lastErr = err
		}
	}
	return "", fmt.Errorf("mockipa: SGP.26 software eUICC fixture unavailable at %s: %w", path, lastErr)
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("mockipa: open %s in SGP.26 fixture: %w", file.Name, err)
	}
	defer func() {
		_ = reader.Close()
	}()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("mockipa: read %s in SGP.26 fixture: %w", file.Name, err)
	}
	return data, nil
}

func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
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
	return nil, fmt.Errorf("mockipa: parse SGP.26 eUICC private key")
}
