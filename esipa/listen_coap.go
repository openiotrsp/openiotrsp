package esipa

import (
	"context"
	"fmt"

	piondtls "github.com/pion/dtls/v3"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
)

// DTLSServerConfig configures the demo CoAP/DTLS ESipa listener.
type DTLSServerConfig struct {
	ListenAddr  string
	PSKIdentity string
	PSKKey      string
}

// ListenCoAPDTLS serves ESipa over CoAP/DTLS using PSK authentication.
func (h *Handler) ListenCoAPDTLS(ctx context.Context, cfg DTLSServerConfig) error {
	if h == nil {
		return fmt.Errorf("esipa: nil handler")
	}
	if cfg.ListenAddr == "" {
		return fmt.Errorf("esipa: missing CoAP/DTLS listen address")
	}
	identity := cfg.PSKIdentity
	if identity == "" {
		identity = DefaultDTLSPSKIdentity
	}
	key := cfg.PSKKey
	if key == "" {
		key = DefaultDTLSPSKKey
	}
	return h.ListenAndServeCoAPDTLS(ctx, "udp", cfg.ListenAddr, coapnet.NewDTLSServerOptions(
		piondtls.WithPSK(func([]byte) ([]byte, error) { return []byte(key), nil }),
		piondtls.WithPSKIdentityHint([]byte(identity)),
		piondtls.WithCipherSuites(piondtls.TLS_PSK_WITH_AES_128_CCM_8),
	))
}
