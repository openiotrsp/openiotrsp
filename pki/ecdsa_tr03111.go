package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
)

// SignECDSATR03111 signs digest with ECDSA and returns BSI TR-03111 encoding (r||s).
func SignECDSATR03111(rand io.Reader, key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, key, digest)
	if err != nil {
		return nil, err
	}
	return MarshalECDSATR03111(r, s, key.Curve)
}

// MarshalECDSATR03111 encodes ECDSA (r, s) as fixed-width BSI TR-03111 bytes.
func MarshalECDSATR03111(r, s *big.Int, curve elliptic.Curve) ([]byte, error) {
	size := (curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return sig, nil
}

// VerifyECDSATR03111 verifies a BSI TR-03111 ECDSA signature over digest.
func VerifyECDSATR03111(pub *ecdsa.PublicKey, digest, sig []byte) (bool, error) {
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return false, fmt.Errorf("pki: TR-03111 signature length %d, want %d", len(sig), 2*size)
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(pub, digest, r, s), nil
}
