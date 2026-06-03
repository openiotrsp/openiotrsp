package esipa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openiotrsp/openiotrsp/storage"
	coap "github.com/plgd-dev/go-coap/v3"
	dtlsserver "github.com/plgd-dev/go-coap/v3/dtls/server"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/net/blockwise"
	"github.com/plgd-dev/go-coap/v3/options"
)

const coapResponseBlockSZX = blockwise.SZX1024

// NewCoAPHandler returns a CoAP mux for the ESipa endpoint.
func NewCoAPHandler(store storage.Store, tenantID storage.TenantID) mux.Handler {
	return NewHandler(store, tenantID).CoAPHandler()
}

// CoAPHandler returns the CoAP wrapper around the shared ESipa handler.
func (h *Handler) CoAPHandler() mux.Handler {
	router := mux.NewRouter()
	_ = router.Handle(h.path(), mux.HandlerFunc(h.ServeCoAP))
	return router
}

// ServeCoAP decodes one BER-TLV ESipa request, invokes Handle, and writes the
// BER-TLV ESipa response.
func (h *Handler) ServeCoAP(w mux.ResponseWriter, r *mux.Message) {
	if r.Code() != codes.POST {
		_ = w.SetResponse(codes.MethodNotAllowed, message.TextPlain, nil)
		return
	}
	body := r.Body()
	if body == nil {
		body = strings.NewReader("")
	}
	payload, err := io.ReadAll(io.LimitReader(body, h.maxMessageSize()+1))
	if err != nil {
		_ = w.SetResponse(codes.BadRequest, message.TextPlain, strings.NewReader(fmt.Sprintf("read ESipa request: %v", err)))
		return
	}
	if int64(len(payload)) > h.maxMessageSize() {
		_ = w.SetResponse(codes.RequestEntityTooLarge, message.TextPlain, strings.NewReader("ESipa request too large"))
		return
	}
	cacheKey := coapBlockwiseCacheKey(w, r)
	if len(payload) == 0 && r.HasOption(message.Block2) && cacheKey != "" {
		if responsePayload, ok := h.cachedBlockwiseResponse(cacheKey); ok {
			blockPayload, opts, err := coapBlock2Response(responsePayload, r)
			if err != nil {
				_ = w.SetResponse(codes.BadRequest, message.TextPlain, strings.NewReader(fmt.Sprintf("read ESipa block2 request: %v", err)))
				return
			}
			_ = w.SetResponse(codes.Content, message.AppOctets, bytes.NewReader(blockPayload), opts...)
			return
		}
	}
	encoded, err := h.handleEncodedResponse(r.Context(), payload)
	if err != nil {
		_ = w.SetResponse(codes.BadRequest, message.TextPlain, strings.NewReader(fmt.Sprintf("handle ESipa request: %v", err)))
		return
	}
	if encoded.NoContent {
		_ = w.SetResponse(codes.Changed, message.AppOctets, nil)
		return
	}
	responsePayload := encoded.Payload
	if cacheKey != "" {
		h.cacheBlockwiseResponse(cacheKey, responsePayload)
	}
	if blockPayload, opts, ok, err := coapFirstBlock2Response(responsePayload); err != nil {
		_ = w.SetResponse(codes.BadRequest, message.TextPlain, strings.NewReader(fmt.Sprintf("write ESipa block2 response: %v", err)))
		return
	} else if ok {
		_ = w.SetResponse(codes.Content, message.AppOctets, bytes.NewReader(blockPayload), opts...)
		return
	}
	_ = w.SetResponse(codes.Content, message.AppOctets, bytes.NewReader(responsePayload))
}

// ListenAndServeCoAPDTLS serves ESipa over CoAP/DTLS with block-wise transfer
// enabled for large eUICC package payloads.
func (h *Handler) ListenAndServeCoAPDTLS(ctx context.Context, network string, addr string, cfg coapnet.DTLSServerOptions, opts ...dtlsserver.Option) error {
	base := []dtlsserver.Option{
		options.WithContext(ctx),
		options.WithMux(h.CoAPHandler()),
		options.WithMaxMessageSize(uint32(h.maxMessageSize())),
		options.WithBlockwise(false, coapResponseBlockSZX, time.Minute),
	}
	base = append(base, opts...)
	return coap.ListenAndServeDTLSWithOptions(network, addr, cfg, base...)
}

type coapBlockwiseResponse struct {
	payload []byte
	expires time.Time
}

func coapBlockwiseCacheKey(w mux.ResponseWriter, r *mux.Message) string {
	if r == nil || w == nil || w.Conn() == nil || w.Conn().RemoteAddr() == nil {
		return ""
	}
	path, err := r.Path()
	if err != nil {
		return ""
	}
	return w.Conn().RemoteAddr().String() + "\x00" + path
}

func (h *Handler) cachedBlockwiseResponse(key string) ([]byte, bool) {
	h.blockwiseMu.Lock()
	defer h.blockwiseMu.Unlock()
	response, ok := h.blockwiseResponses[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(response.expires) {
		delete(h.blockwiseResponses, key)
		return nil, false
	}
	return cloneBytes(response.payload), true
}

func (h *Handler) cacheBlockwiseResponse(key string, response []byte) {
	h.blockwiseMu.Lock()
	defer h.blockwiseMu.Unlock()
	if h.blockwiseResponses == nil {
		h.blockwiseResponses = make(map[string]coapBlockwiseResponse)
	}
	now := time.Now()
	for key, cached := range h.blockwiseResponses {
		if now.After(cached.expires) {
			delete(h.blockwiseResponses, key)
		}
	}
	h.blockwiseResponses[key] = coapBlockwiseResponse{
		payload: cloneBytes(response),
		expires: now.Add(time.Minute),
	}
}

func coapFirstBlock2Response(response []byte) ([]byte, []message.Option, bool, error) {
	if int64(len(response)) <= coapResponseBlockSZX.Size() {
		return nil, nil, false, nil
	}
	payload, opts, err := coapBlock2Chunk(response, coapResponseBlockSZX, 0)
	return payload, opts, true, err
}

func coapBlock2Response(response []byte, r *mux.Message) ([]byte, []message.Option, error) {
	requested, err := r.GetOptionUint32(message.Block2)
	if err != nil {
		return nil, nil, err
	}
	szx, blockNumber, _, err := blockwise.DecodeBlockOption(requested)
	if err != nil {
		return nil, nil, err
	}
	return coapBlock2Chunk(response, szx, blockNumber)
}

func coapBlock2Chunk(response []byte, szx blockwise.SZX, blockNumber int64) ([]byte, []message.Option, error) {
	blockSize := szx.Size()
	if blockSize <= 0 {
		return nil, nil, fmt.Errorf("invalid block size %d", blockSize)
	}
	start := blockNumber * blockSize
	if start > int64(len(response)) {
		return nil, nil, fmt.Errorf("block %d starts beyond response size %d", blockNumber, len(response))
	}
	end := min(start+blockSize, int64(len(response)))
	more := end < int64(len(response))
	blockValue, err := blockwise.EncodeBlockOption(szx, blockNumber, more)
	if err != nil {
		return nil, nil, err
	}
	blockOption, err := coapUintOption(message.Block2, blockValue)
	if err != nil {
		return nil, nil, err
	}
	sizeOption, err := coapUintOption(message.Size2, uint32(len(response)))
	if err != nil {
		return nil, nil, err
	}
	return cloneBytes(response[start:end]), []message.Option{blockOption, sizeOption}, nil
}

func coapUintOption(id message.OptionID, value uint32) (message.Option, error) {
	buffer := make([]byte, 4)
	used, err := message.EncodeUint32(buffer, value)
	if err != nil {
		return message.Option{}, err
	}
	return message.Option{ID: id, Value: buffer[:used]}, nil
}
