package pki

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// DefaultSGP26VariantONISTDemoEID is the EID carried by the SGP.26 Variant O
// NIST test eUICC certificate used by the live mock IPA demo.
const DefaultSGP26VariantONISTDemoEID = "89049032123451234512345678901235"

// EIDHexFromCertificate returns the 32-digit lowercase hex EID encoded in an
// eUICC certificate subject serialNumber.
func EIDHexFromCertificate(certDER []byte) (string, error) {
	if len(certDER) == 0 {
		return "", fmt.Errorf("pki: missing eUICC certificate")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("pki: parse eUICC certificate: %w", err)
	}
	eid := strings.TrimSpace(cert.Subject.SerialNumber)
	if len(eid) != 32 {
		return "", fmt.Errorf("pki: eUICC certificate serialNumber %q is not a 32-digit EID", cert.Subject.SerialNumber)
	}
	if _, err := hex.DecodeString(eid); err != nil {
		return "", fmt.Errorf("pki: eUICC certificate serialNumber %q is not valid hex: %w", eid, err)
	}
	return strings.ToLower(eid), nil
}
