package mockipa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/openiotrsp/openiotrsp/esipa"
	piondtls "github.com/pion/dtls/v3"
	coapdtls "github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/net/blockwise"
	"github.com/plgd-dev/go-coap/v3/options"
	udpclient "github.com/plgd-dev/go-coap/v3/udp/client"
)

// CoAPTransport posts ESipa messages over CoAP/DTLS.
type CoAPTransport struct {
	Endpoint    string
	Path        string
	PSKIdentity string
	PSKKey      string

	mu     sync.Mutex
	client *udpclient.Conn
}

// Exchange implements Transport.
func (t *CoAPTransport) Exchange(ctx context.Context, payload []byte) ([]byte, bool, error) {
	client, err := t.coapClient()
	if err != nil {
		return nil, false, err
	}
	path := t.Path
	if path == "" {
		path = esipa.DefaultPath
	}
	response, err := client.Post(ctx, path, message.AppOctets, bytes.NewReader(payload))
	if err != nil {
		return nil, false, err
	}
	switch response.Code() {
	case codes.Changed:
		body, readErr := io.ReadAll(response.Body())
		if readErr != nil {
			return nil, false, readErr
		}
		if len(body) != 0 {
			return nil, false, fmt.Errorf("mockipa: CoAP Changed response carried %d unexpected bytes", len(body))
		}
		return nil, true, nil
	case codes.Content:
		body, readErr := io.ReadAll(response.Body())
		if readErr != nil {
			return nil, false, readErr
		}
		return body, false, nil
	default:
		body, _ := io.ReadAll(response.Body())
		return nil, false, fmt.Errorf("mockipa: CoAP returned %v: %s", response.Code(), string(body))
	}
}

func (t *CoAPTransport) coapClient() (*udpclient.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	identity := t.PSKIdentity
	if identity == "" {
		identity = esipa.DefaultDTLSPSKIdentity
	}
	key := t.PSKKey
	if key == "" {
		key = esipa.DefaultDTLSPSKKey
	}
	client, err := coapdtls.Dial(t.Endpoint, coapdtls.NewDTLSClientOptions(
		piondtls.WithInsecureSkipVerify(true),
		piondtls.WithPSK(func([]byte) ([]byte, error) { return []byte(key), nil }),
		piondtls.WithPSKIdentityHint([]byte(identity)),
		piondtls.WithCipherSuites(piondtls.TLS_PSK_WITH_AES_128_CCM_8),
	),
		options.WithBlockwise(true, blockwise.SZX1024, time.Minute),
		options.WithMaxMessageSize(1<<20),
	)
	if err != nil {
		return nil, err
	}
	t.client = client
	return t.client, nil
}

// Close releases the CoAP/DTLS session.
func (t *CoAPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == nil {
		return nil
	}
	err := t.client.Close()
	<-t.client.Done()
	t.client = nil
	return err
}
