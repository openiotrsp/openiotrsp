package mockipa

import (
	"context"
)

// Transport exchanges BER-TLV ESipa payloads with an eIM.
type Transport interface {
	Exchange(ctx context.Context, payload []byte) (response []byte, noContent bool, err error)
}
