package esipa

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/openiotrsp/openiotrsp/pki"
	"github.com/openiotrsp/openiotrsp/storage"
)

// NewStaticEUICCCertificateResolver validates a single SGP.26 eUICC certificate
// chain and returns a resolver for deployments or tests where one eUICC key is
// expected.
func NewStaticEUICCCertificateResolver(ciDER, eumDER, euiccDER []byte, opts ...pki.Option) (EUICCPublicKeyResolver, error) {
	if len(ciDER) == 0 || len(eumDER) == 0 || len(euiccDER) == 0 {
		return nil, errors.New("esipa: CI, EUM, and eUICC certificates are required")
	}
	validator, err := pki.NewValidator([][]byte{ciDER}, opts...)
	if err != nil {
		return nil, err
	}
	if err := validator.ValidateEUICCChain([][]byte{euiccDER, eumDER}); err != nil {
		return nil, err
	}
	euicc, err := x509.ParseCertificate(euiccDER)
	if err != nil {
		return nil, fmt.Errorf("esipa: parse eUICC certificate: %w", err)
	}
	publicKey := euicc.PublicKey
	return func(context.Context, storage.TenantID, string) (crypto.PublicKey, error) {
		return publicKey, nil
	}, nil
}
