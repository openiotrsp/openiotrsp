package file

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/openiotrsp/openiotrsp/signing"
)

var _ signing.Signer = (*Signer)(nil)

// Signer signs eIM payloads with an ECDSA private key loaded from disk.
type Signer struct {
	key     *ecdsa.PrivateKey
	certDER []byte
}

// Load loads an ECDSA private key and eIM certificate from PEM or DER files.
func Load(keyPath, certPath string) (*Signer, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ECDSA private key: %w", err)
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read eIM certificate: %w", err)
	}
	return New(keyBytes, certBytes)
}

// New creates a file-backed signer from PEM or DER encoded key and certificate bytes.
func New(keyBytes, certBytes []byte) (*Signer, error) {
	keyDER, err := decodePEMOrDER(keyBytes, "EC PRIVATE KEY", "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("decode ECDSA private key: %w", err)
	}
	certDER, err := decodePEMOrDER(certBytes, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("decode eIM certificate: %w", err)
	}

	key, err := parseECDSAPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	if err := certificateMatchesKey(certDER, &key.PublicKey); err != nil {
		return nil, err
	}

	return &Signer{
		key:     key,
		certDER: append([]byte(nil), certDER...),
	}, nil
}

// Sign signs payload with ECDSA over SHA-256 and returns an ASN.1 DER ECDSA signature.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}
	return signature, nil
}

// PublicKey returns the eIM public key corresponding to the signing key.
func (s *Signer) PublicKey() crypto.PublicKey {
	return &s.key.PublicKey
}

// CertificateDER returns a copy of the loaded eIM certificate.
func (s *Signer) CertificateDER() []byte {
	return append([]byte(nil), s.certDER...)
}

func decodePEMOrDER(data []byte, allowedTypes ...string) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("empty input")
	}

	block, rest := pem.Decode(trimmed)
	if block == nil {
		return append([]byte(nil), trimmed...), nil
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after PEM block")
	}
	for _, allowedType := range allowedTypes {
		if block.Type == allowedType {
			return append([]byte(nil), block.Bytes...), nil
		}
	}
	return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
}

func parseECDSAPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse ECDSA private key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key type %T is not ECDSA", key)
	}
	return ecdsaKey, nil
}

func certificateMatchesKey(certDER []byte, publicKey *ecdsa.PublicKey) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse eIM certificate: %w", err)
	}
	certPublicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("eIM certificate public key type %T is not ECDSA", cert.PublicKey)
	}
	certPublicKeyDER, err := x509.MarshalPKIXPublicKey(certPublicKey)
	if err != nil {
		return fmt.Errorf("marshal eIM certificate public key: %w", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal ECDSA private key public key: %w", err)
	}
	if !bytes.Equal(certPublicKeyDER, publicKeyDER) {
		return errors.New("eIM certificate public key does not match private key")
	}
	return nil
}
