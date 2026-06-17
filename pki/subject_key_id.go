package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// SubjectKeyIdentifier returns the SubjectKeyIdentifier for a certificate,
// falling back to the SHA-256 hash of the subject public key info when absent.
func SubjectKeyIdentifier(certDER []byte) ([]byte, error) {
	if len(certDER) == 0 {
		return nil, fmt.Errorf("pki: missing certificate")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}
	if len(cert.SubjectKeyId) > 0 {
		return cloneBytes(cert.SubjectKeyId), nil
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:], nil
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
