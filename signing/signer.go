package signing

import (
	"context"
	"crypto"
)

// Signer signs eIM payloads and exposes the public material used to verify them.
type Signer interface {
	Sign(ctx context.Context, payload []byte) ([]byte, error)
	PublicKey() crypto.PublicKey
	CertificateDER() []byte
}
