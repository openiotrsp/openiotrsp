package mockipa

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/openiotrsp/openiotrsp/pki"
)

// SGP26Fixture contains the material needed by the software eUICC.
type SGP26Fixture struct {
	CICertificate    []byte
	EUICCCertificate []byte
	EUMCertificate   []byte
	EIMCertificate   []byte
	EUICCKey         *ecdsa.PrivateKey
	EIMKey           *ecdsa.PrivateKey
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
	material, err := pki.LoadSGP26VariantONISTMaterial(path)
	if err != nil {
		return nil, fmt.Errorf("mockipa: %w", err)
	}
	return &SGP26Fixture{
		CICertificate:    material.CICertificate,
		EUICCCertificate: material.EUICCCertificate,
		EUMCertificate:   material.EUMCertificate,
		EIMCertificate:   material.EIMCertificate,
		EUICCKey:         material.EUICCKey,
		EIMKey:           material.EIMKey,
		EID:              material.EID,
	}, nil
}

func resolveFixturePath(path string) (string, error) {
	return pki.ResolveFixturePath(path)
}
