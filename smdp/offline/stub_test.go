package offline

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStubLabelsOfflineFallback(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(NewHandler())
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %s", response.Status)
	}
	contentType := response.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Fatalf("Content-Type = %q", contentType)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !strings.Contains(string(body), "offline-stub-not-signature-proof") {
		t.Fatalf("body = %s, want offline stub warning", string(body))
	}
}
