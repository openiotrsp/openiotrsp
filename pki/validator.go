package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// Validator validates GSMA-style ECDSA certificate chains against explicit roots.
type Validator struct {
	roots     *x509.CertPool
	rootCerts []*x509.Certificate
	now       func() time.Time
}

// Option configures a Validator.
type Option func(*Validator)

// WithCurrentTime fixes the validation time. It is primarily useful for tests.
func WithCurrentTime(now time.Time) Option {
	return func(v *Validator) {
		v.now = func() time.Time { return now }
	}
}

// NewValidator creates a chain validator using only the supplied root certificates.
func NewValidator(rootDER [][]byte, opts ...Option) (*Validator, error) {
	if len(rootDER) == 0 {
		return nil, errors.New("pki: no trusted roots configured")
	}

	v := &Validator{
		roots: x509.NewCertPool(),
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}

	for i, der := range rootDER {
		root, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("pki: parse trusted root %d: %w", i, err)
		}
		if _, ok := root.PublicKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("pki: trusted root %d is not an ECDSA certificate", i)
		}
		if !root.IsCA {
			return nil, fmt.Errorf("pki: trusted root %d is not a CA", i)
		}
		if root.KeyUsage != 0 && root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("pki: trusted root %d cannot sign certificates", i)
		}
		if err := root.CheckSignatureFrom(root); err != nil {
			return nil, fmt.Errorf("pki: trusted root %d self-signature invalid: %w", i, err)
		}
		v.roots.AddCert(root)
		v.rootCerts = append(v.rootCerts, root)
	}

	return v, nil
}

// ValidateChain validates a leaf-first chain. The configured root may be omitted
// or supplied as the final certificate, but it must exactly match a trusted root.
func (v *Validator) ValidateChain(chainDER [][]byte) error {
	if len(chainDER) == 0 {
		return errors.New("pki: empty certificate chain")
	}

	chain := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("pki: parse certificate %d: %w", i, err)
		}
		if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("pki: certificate %d is not an ECDSA certificate", i)
		}
		chain = append(chain, cert)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("pki: verify certificate chain: %w", err)
	}
	return nil
}

// ValidateEUICCChain validates a CERT.EUICC.ECDSA -> CERT.EUM.ECDSA chain.
//
// SGP.26 EUM certificates can carry critical directory-name name constraints
// that Go's generic RFC 5280 verifier cannot apply to eUICC EID subjects. This
// path keeps the standard parser and ECDSA signature checks, but deliberately
// avoids generic name-constraint subtree enforcement for the EUM certificate.
func (v *Validator) ValidateEUICCChain(chainDER [][]byte) error {
	if len(chainDER) != 2 && len(chainDER) != 3 {
		return fmt.Errorf("pki: eUICC chain must contain eUICC and EUM certificates, with optional CI root; got %d certificates", len(chainDER))
	}

	euicc, err := parseP256ECDSACertificate(chainDER[0], "eUICC certificate")
	if err != nil {
		return err
	}
	eum, err := parseP256ECDSACertificate(chainDER[1], "EUM certificate")
	if err != nil {
		return err
	}

	root, err := v.euiccChainRoot(chainDER)
	if err != nil {
		return err
	}

	now := v.now()
	for label, cert := range map[string]*x509.Certificate{
		"eUICC certificate": euicc,
		"EUM certificate":   eum,
		"CI root":           root,
	} {
		if err := validateCertificateTime(cert, now); err != nil {
			return fmt.Errorf("pki: %s %w", label, err)
		}
	}

	if err := rejectUnhandledCriticalExtensions(euicc, nil); err != nil {
		return fmt.Errorf("pki: eUICC certificate: %w", err)
	}
	if err := rejectUnhandledCriticalExtensions(eum, []asn1.ObjectIdentifier{oidExtensionNameConstraints}); err != nil {
		return fmt.Errorf("pki: EUM certificate: %w", err)
	}
	if err := rejectUnhandledCriticalExtensions(root, nil); err != nil {
		return fmt.Errorf("pki: CI root: %w", err)
	}

	if euicc.IsCA {
		return errors.New("pki: eUICC certificate must not be a CA")
	}
	if euicc.KeyUsage != 0 && euicc.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("pki: eUICC certificate cannot create digital signatures")
	}
	if !eum.IsCA {
		return errors.New("pki: EUM certificate is not a CA")
	}
	if eum.KeyUsage != 0 && eum.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("pki: EUM certificate cannot sign certificates")
	}

	if err := checkIssuedBy(euicc, eum, "eUICC certificate", "EUM certificate"); err != nil {
		return err
	}
	if err := checkIssuedBy(eum, root, "EUM certificate", "CI root"); err != nil {
		return err
	}
	return nil
}

func (v *Validator) euiccChainRoot(chainDER [][]byte) (*x509.Certificate, error) {
	if len(chainDER) == 3 {
		includedRoot, err := parseP256ECDSACertificate(chainDER[2], "CI root")
		if err != nil {
			return nil, err
		}
		for _, root := range v.rootCerts {
			if bytes.Equal(includedRoot.Raw, root.Raw) {
				return root, nil
			}
		}
		return nil, errors.New("pki: included CI root is not trusted")
	}

	eum, err := x509.ParseCertificate(chainDER[1])
	if err != nil {
		return nil, fmt.Errorf("pki: parse EUM certificate: %w", err)
	}
	var signatureErr error
	for _, root := range v.rootCerts {
		if !bytes.Equal(eum.RawIssuer, root.RawSubject) {
			continue
		}
		if err := eum.CheckSignatureFrom(root); err != nil {
			signatureErr = err
			continue
		}
		return root, nil
	}
	if signatureErr != nil {
		return nil, fmt.Errorf("pki: EUM certificate signature rejected by trusted CI root: %w", signatureErr)
	}
	return nil, errors.New("pki: no trusted CI root for EUM certificate")
}

func parseP256ECDSACertificate(der []byte, label string) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse %s: %w", label, err)
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pki: %s is not an ECDSA certificate", label)
	}
	if publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("pki: %s is not a P-256 certificate", label)
	}
	return cert, nil
}

func validateCertificateTime(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("is not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func rejectUnhandledCriticalExtensions(cert *x509.Certificate, allowed []asn1.ObjectIdentifier) error {
	for _, extension := range cert.UnhandledCriticalExtensions {
		if oidAllowed(extension, allowed) {
			continue
		}
		return fmt.Errorf("unsupported critical extension %s", extension.String())
	}
	return nil
}

func oidAllowed(oid asn1.ObjectIdentifier, allowed []asn1.ObjectIdentifier) bool {
	for _, candidate := range allowed {
		if oid.Equal(candidate) {
			return true
		}
	}
	return false
}

func checkIssuedBy(child, parent *x509.Certificate, childLabel, parentLabel string) error {
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return fmt.Errorf("pki: %s issuer does not match %s subject", childLabel, parentLabel)
	}
	if err := child.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("pki: %s signature rejected by %s: %w", childLabel, parentLabel, err)
	}
	return nil
}

var oidExtensionNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
