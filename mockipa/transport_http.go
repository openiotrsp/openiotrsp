package mockipa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openiotrsp/openiotrsp/esipa"
)

// HTTPTransport posts ESipa messages over HTTPS.
type HTTPTransport struct {
	Endpoint   string
	HTTPClient *http.Client
}

// Exchange implements Transport.
func (t HTTPTransport) Exchange(ctx context.Context, payload []byte) ([]byte, bool, error) {
	client := t.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, false, err
	}
	// SGP.32 v1.3 sections 6.1 and 6.1.1 mandate these three request headers on
	// the ASN.1 binding. gsma-rsp-ipad is the User-Agent for an IPA in the
	// device rather than in the eUICC.
	request.Header.Set("Content-Type", esipa.ASN1MediaType)
	request.Header.Set("X-Admin-Protocol", esipa.DefaultAdminProtocol)
	request.Header.Set("User-Agent", "gsma-rsp-ipad")
	response, err := client.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, false, err
	}
	if response.StatusCode == http.StatusNoContent {
		if len(body) != 0 {
			return nil, false, fmt.Errorf("mockipa: ESipa notification returned %s with body", response.Status)
		}
		return nil, true, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("mockipa: ESipa returned %s: %s", response.Status, string(body))
	}
	return body, false, nil
}
