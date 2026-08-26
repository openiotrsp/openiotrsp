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
// It mounts the SGP.32 ASN.1 binding on GSMAPathASN1, the GSMA JSON binding on
// DefaultGSMAPaths, and the legacy BER-TLV DefaultPath, so one handler serves
// both an IPAe and an IPAd out of the box.
func (h *Handler) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(GSMAPathASN1, h.ServeHTTP)
	if path := h.path(); path != GSMAPathASN1 {
		mux.HandleFunc(path, h.ServeHTTP)
	}
	for _, gsmaPath := range DefaultGSMAPaths {
		mux.HandleFunc(gsmaPath, h.ServeGSMAJSON)
	}
	return mux
}

// ServeHTTP decodes one ASN.1 ESipa request, invokes Handle, and writes the
// ASN.1 ESipa response per SGP.32 v1.3 section 6.1.1. The request Content-Type
// is not inspected: the binding is selected by path, and rejecting an IPA over
// a header it got wrong would only cost interoperability.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	setAdminProtocolResponse(w, r.Header.Get(adminProtocolHeader))
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
	encoded, err := h.handleEncodedResponse(r.Context(), payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("handle ESipa request: %v", err), http.StatusBadRequest)
		return
	}
	if encoded.NoContent {
		// SGP.32 v1.3 section 6.1.1: a normal notification execution answers
		// 204 with an empty body, and SGP.22 section 6.2 says not to set
		// Content-Type when the body is empty.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", ASN1MediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded.Payload)
}

type encodedResponse struct {
	Payload   []byte
	NoContent bool
}

func (h *Handler) handleEncodedResponse(ctx context.Context, payload []byte) (encodedResponse, error) {
	request, err := DecodeRequest(payload)
	if err != nil {
		return encodedResponse{}, err
	}
	response, err := h.handle(ctx, request)
	if err != nil {
		return encodedResponse{}, err
	}
	if response.Message.Raw == nil {
		return encodedResponse{NoContent: true}, nil
	}
	encoded, err := EncodeResponse(response)
	if err != nil {
		return encodedResponse{}, err
	}
	return encodedResponse{Payload: encoded}, nil
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
