package euiccpkg

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

// NewInitialEIMConfigurationData builds the EimConfigurationData handed to an
// ES10b AddInitialEim bootstrap flow. The association token is optional here
// because it is returned by the eUICC after bootstrap.
func NewInitialEIMConfigurationData(
	eimID string,
	eimFQDN string,
	counterValue int64,
	publicKeyDER []byte,
	associationToken *int64,
) (*protocolasn1.EimConfigurationData, error) {
	config, err := NewEIMConfigurationData(eimID, eimFQDN, counterValue, publicKeyDER)
	if err != nil {
		return nil, err
	}
	setAssociationToken(config, associationToken)
	return config, nil
}

// NewInitialEIMConfigurationDataFromPublicKey builds bootstrap configuration
// from a crypto public key encoded as X.509 SubjectPublicKeyInfo.
func NewInitialEIMConfigurationDataFromPublicKey(
	eimID string,
	eimFQDN string,
	counterValue int64,
	publicKey crypto.PublicKey,
	associationToken *int64,
) (*protocolasn1.EimConfigurationData, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal eIM public key: %w", err)
	}
	return NewInitialEIMConfigurationData(eimID, eimFQDN, counterValue, publicKeyDER, associationToken)
}

// NewInitialEIMConfigurationDataFromCertificate builds bootstrap configuration
// from a raw X.509 certificate DER.
func NewInitialEIMConfigurationDataFromCertificate(
	eimID string,
	eimFQDN string,
	counterValue int64,
	certificateDER []byte,
	associationToken *int64,
) (*protocolasn1.EimConfigurationData, error) {
	config, err := NewEIMConfigurationDataFromCertificate(eimID, eimFQDN, counterValue, certificateDER)
	if err != nil {
		return nil, err
	}
	setAssociationToken(config, associationToken)
	return config, nil
}

// ValidateInitialEIMConfigurationData checks the fields required for
// AddInitialEim/ECO trust establishment. AssociationToken is intentionally not
// required here because it is returned by the eUICC after the unsigned bootstrap
// path succeeds.
func ValidateInitialEIMConfigurationData(config *protocolasn1.EimConfigurationData) error {
	if config == nil {
		return errors.New("euiccpkg: missing EimConfigurationData")
	}
	if len(config.EimID) == 0 || len(config.EimID) > 128 {
		return errors.New("euiccpkg: eimId must be 1..128 characters")
	}
	if config.EimFQDN == nil || strings.TrimSpace(*config.EimFQDN) == "" {
		return errors.New("euiccpkg: eimFQDN is required for initial provisioning")
	}
	if config.CounterValue == nil {
		return errors.New("euiccpkg: counterValue is required")
	}
	if *config.CounterValue < 0 {
		return errors.New("euiccpkg: counterValue must be non-negative")
	}
	if config.EimPublicKeyData == nil || config.EimPublicKeyData.Data == nil {
		return errors.New("euiccpkg: eimPublicKeyData is required")
	}
	return nil
}

func setAssociationToken(config *protocolasn1.EimConfigurationData, token *int64) {
	if token == nil {
		return
	}
	value := *token
	config.AssociationToken = &value
}
