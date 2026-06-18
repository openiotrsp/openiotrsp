package mockipa

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openiotrsp/openiotrsp/esipa"
)

// NewTransportFromEndpoint builds the ESipa transport for endpoint.
// Supports http(s):// and coaps:// URLs.
func NewTransportFromEndpoint(endpoint string, httpClient *http.Client) (Transport, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("mockipa: missing ESipa endpoint")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mockipa: parse ESipa endpoint: %w", err)
	}
	switch parsed.Scheme {
	case "http", "https":
		if httpClient == nil {
			httpClient = &http.Client{Timeout: 30 * time.Second}
		}
		return HTTPTransport{Endpoint: endpoint, HTTPClient: httpClient}, nil
	case "coaps":
		path := parsed.Path
		if path == "" {
			path = esipa.DefaultPath
		}
		return &CoAPTransport{
			Endpoint: parsed.Host,
			Path:     path,
		}, nil
	default:
		return nil, fmt.Errorf("mockipa: unsupported ESipa endpoint scheme %q", parsed.Scheme)
	}
}
