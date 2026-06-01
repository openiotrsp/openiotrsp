package esipa

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/openiotrsp/openiotrsp/storage"
)

// NewHTTPHandler returns a stdlib HTTP handler for the ESipa endpoint.
func NewHTTPHandler(store storage.Store, tenantID storage.TenantID) http.Handler {
	return NewHandler(store, tenantID).HTTPHandler()
}

// HTTPHandler returns the stdlib HTTP wrapper around the shared ESipa handler.
func (h *Handler) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	path := h.path()
	mux.HandleFunc(path, h.ServeHTTP)
	return mux
}

// ServeHTTP decodes one BER-TLV ESipa request, invokes Handle, and writes the
// BER-TLV ESipa response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	maxSize := h.maxMessageSize()
	body := http.MaxBytesReader(w, r.Body, maxSize)
	defer func() {
		_ = r.Body.Close()
	}()

	payload, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read ESipa request: %v", err), http.StatusBadRequest)
		return
	}
	responsePayload, err := h.handleEncoded(r.Context(), payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("handle ESipa request: %v", err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responsePayload)
}

func (h *Handler) handleEncoded(ctx context.Context, payload []byte) ([]byte, error) {
	request, err := DecodeRequest(payload)
	if err != nil {
		return nil, err
	}
	response, err := Handle(ctx, h.Store, h.TenantID, request)
	if err != nil {
		return nil, err
	}
	return EncodeResponse(response)
}

func (h *Handler) path() string {
	if h == nil || h.Path == "" {
		return DefaultPath
	}
	return h.Path
}

func (h *Handler) maxMessageSize() int64 {
	if h == nil || h.MaxMessageSize <= 0 {
		return DefaultMaxMessageSize
	}
	return h.MaxMessageSize
}
