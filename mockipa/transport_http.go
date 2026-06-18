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
	request.Header.Set("Content-Type", esipa.MediaType)
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
