package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestSignECDSATR03111Produces64ByteSignature(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	digest := sha256.Sum256([]byte("openiotrsp"))
	sig, err := SignECDSATR03111(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignECDSATR03111() error = %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}
	ok, err := VerifyECDSATR03111(&key.PublicKey, digest[:], sig)
	if err != nil {
		t.Fatalf("VerifyECDSATR03111() error = %v", err)
	}
	if !ok {
		t.Fatal("TR-03111 signature did not verify")
	}
}
