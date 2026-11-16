package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/message/pool"
	"github.com/plgd-dev/go-coap/v3/mux"
	"github.com/plgd-dev/go-coap/v3/net/blockwise"
)

func TestBlock2TransferStaysAliveWhileTheCardReads(t *testing.T) {
	t.Parallel()

	fx := newBlockDownload(t)
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	fx.handler.now = func() time.Time { return now }
	conn := blockConn{addr: stringAddr("192.0.2.10:5684")}
	fx.open(t, conn)
	if len(fx.handler.blockwiseResponses) != 0 {
		t.Fatal("a response smaller than one block created a Block2 cache entry")
	}

	const block = 1024
	if len(fx.payload) <= 2*block {
		t.Fatalf("payload length %d, want more than two blocks", len(fx.payload))
	}
	first := serveBlock(t, fx.handler, conn, fx.bound, nil)
	assertBlock(t, first, fx.payload[:block], true)
	if len(fx.handler.blockwiseResponses) != 1 {
		t.Fatalf("cache entries = %d, want 1", len(fx.handler.blockwiseResponses))
	}
	for _, cached := range fx.handler.blockwiseResponses {
		if !bytes.Equal(cached.payload, fx.payload) {
			t.Fatal("cached payload bytes changed")
		}
	}

	now = now.Add(10 * time.Second)
	past := serveBlock(t, fx.handler, conn, nil, block2Num(t, 5))
	if past.code != codes.BadRequest {
		t.Fatalf("block past the end = %v body %q, want 4.00", past.code, past.body)
	}

	now = now.Add(35 * time.Second) // 45s after block 0; the past-end request did not refresh
	second := serveBlock(t, fx.handler, conn, nil, block2Num(t, 1))
	assertBlock(t, second, fx.payload[block:2*block], true)

	now = now.Add(45 * time.Second) // 90s after block 0, inside the idle window refreshed above
	last := serveBlock(t, fx.handler, conn, nil, block2Num(t, 2))
	assertBlock(t, last, fx.payload[2*block:], false)
}

func TestBlock2TransferExpiresWhenIdle(t *testing.T) {
	t.Parallel()

	fx := newBlockDownload(t)
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	fx.handler.now = func() time.Time { return now }
	conn := blockConn{addr: stringAddr("192.0.2.20:5684")}
	fx.open(t, conn)

	first := serveBlock(t, fx.handler, conn, fx.bound, nil)
	assertBlock(t, first, fx.payload[:1024], true)

	now = now.Add(blockwiseIdle + time.Second)
	miss := serveBlock(t, fx.handler, conn, nil, block2Num(t, 1))
	if miss.code != codes.BadRequest {
		t.Fatalf("idle Block2 = %v body %q, want 4.00", miss.code, miss.body)
	}
	if bytes.Contains(miss.body, fx.payload[1024:1056]) {
		t.Fatal("cache miss returned the next slice of the profile")
	}
	if bytes.Contains(miss.body, []byte("empty BER-TLV")) {
		t.Fatal("cache miss was parsed as an ESipa message")
	}
	if len(fx.handler.blockwiseResponses) != 0 {
		t.Fatal("idle transfer was kept")
	}
}

func TestEmptyCoAPBodyWithoutBlock2IsRejected(t *testing.T) {
	t.Parallel()

	handler := NewHandler(memory.New(), storage.DefaultTenantID)
	handler.Logger = discardLogger()
	got := serveBlock(t, handler, blockConn{addr: stringAddr("192.0.2.30:5684")}, nil, nil)
	if got.code != codes.BadRequest || !bytes.Contains(got.body, []byte("empty BER-TLV")) {
		t.Fatalf("status %v body %q, want 4.00 from an empty ESipa body", got.code, got.body)
	}
}

type blockDownload struct {
	handler *Handler
	init    []byte
	bound   []byte
	payload []byte
}

func (fx blockDownload) open(t *testing.T, conn blockConn) {
	t.Helper()
	got := serveBlock(t, fx.handler, conn, fx.init, nil)
	if got.code != codes.Content {
		t.Fatalf("InitiateAuthentication status %v body %q", got.code, got.body)
	}
}

func newBlockDownload(t *testing.T) blockDownload {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(0x51))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	info1, err := sampleEUICCInfo1(t).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:             eidKey,
		EUICCInfo1:      info1,
		IPACapabilities: sampleIPACapabilities(t, 0x00),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	eimTx := bytes.Repeat([]byte{0x51}, 16)
	enqueueActivation(t, ctx, store, eidKey, eimTx)
	payload := mustRawSuccess(t, tagGetBoundPackage, true, marshalTLV(t, bertlv.NewChildren(tagBoundPackage,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(6), bytes.Repeat([]byte{0x11}, 2200)),
	)))
	transport := &esipaRecordingTransport{responses: map[relay.Endpoint]relay.Response{
		relay.EndpointInitiateAuthentication: {Payload: mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")},
		relay.EndpointGetBoundProfilePackage: {Payload: payload},
	}}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Logger = discardLogger()
	handler.Relay = relay.New(transport)
	return blockDownload{
		handler: handler,
		init:    mustMarshalInitAuth(t, bytes.Repeat([]byte{0xa5}, 16), "", nil, eimTx),
		bound:   mustGetBoundRequest(t, []byte{0x01, 0x02, 0x03}),
		payload: payload,
	}
}

func assertBlock(t *testing.T, got blockCapture, want []byte, more bool) {
	t.Helper()
	if got.code != codes.Content {
		t.Fatalf("status %v body %q, want 2.05", got.code, got.body)
	}
	if !bytes.Equal(got.body, want) {
		t.Fatalf("block = %d bytes, want %d", len(got.body), len(want))
	}
	raw, ok := blockOption(got.opts, message.Block2)
	if !ok {
		t.Fatal("Block2 option missing")
	}
	_, _, gotMore, err := blockwise.DecodeBlockOption(raw)
	if err != nil {
		t.Fatalf("DecodeBlockOption() error = %v", err)
	}
	if gotMore != more {
		t.Fatalf("more = %v, want %v", gotMore, more)
	}
}

func block2Num(t *testing.T, n int64) *uint32 {
	t.Helper()
	value, err := blockwise.EncodeBlockOption(blockwise.SZX1024, n, false)
	if err != nil {
		t.Fatalf("EncodeBlockOption(%d) error = %v", n, err)
	}
	return &value
}

func blockOption(opts []message.Option, id message.OptionID) (uint32, bool) {
	for _, opt := range opts {
		if opt.ID != id {
			continue
		}
		value, _, err := message.DecodeUint32(opt.Value)
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

type blockCapture struct {
	code codes.Code
	body []byte
	opts []message.Option
}

func serveBlock(t *testing.T, handler *Handler, conn blockConn, body []byte, block *uint32) blockCapture {
	t.Helper()
	msg := pool.NewMessage(context.Background())
	msg.SetCode(codes.POST)
	if err := msg.SetPath(DefaultPath); err != nil {
		t.Fatalf("SetPath() error = %v", err)
	}
	if len(body) > 0 {
		msg.SetBody(bytes.NewReader(body))
	}
	if block != nil {
		msg.SetOptionUint32(message.Block2, *block)
	}
	writer := &blockResponse{conn: conn}
	handler.ServeCoAP(writer, &mux.Message{Message: msg})
	return writer.got
}

type blockResponse struct {
	conn blockConn
	got  blockCapture
}

func (w *blockResponse) SetResponse(code codes.Code, _ message.MediaType, d io.ReadSeeker, opts ...message.Option) error {
	w.got.code = code
	w.got.opts = append([]message.Option(nil), opts...)
	if d == nil {
		return nil
	}
	if _, err := d.Seek(0, io.SeekStart); err != nil {
		return err
	}
	body, err := io.ReadAll(d)
	if err != nil {
		return err
	}
	w.got.body = body
	return nil
}

func (w *blockResponse) Conn() mux.Conn { return w.conn }

func (w *blockResponse) SetMessage(m *pool.Message) {}

func (w *blockResponse) Message() *pool.Message { return nil }

type stringAddr string

func (a stringAddr) Network() string { return "udp" }
func (a stringAddr) String() string  { return string(a) }

type blockConn struct{ addr net.Addr }

func (c blockConn) RemoteAddr() net.Addr                         { return c.addr }
func (c blockConn) AcquireMessage(context.Context) *pool.Message { return nil }
func (c blockConn) ReleaseMessage(*pool.Message)                 {}
func (c blockConn) Ping(context.Context) error                   { return nil }
func (c blockConn) Get(context.Context, string, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) Delete(context.Context, string, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) Post(context.Context, string, message.MediaType, io.ReadSeeker, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) Put(context.Context, string, message.MediaType, io.ReadSeeker, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) Observe(context.Context, string, func(*pool.Message), ...message.Option) (mux.Observation, error) {
	return nil, nil
}
func (c blockConn) NetConn() net.Conn                        { return nil }
func (c blockConn) Context() context.Context                 { return context.Background() }
func (c blockConn) SetContextValue(interface{}, interface{}) {}
func (c blockConn) WriteMessage(*pool.Message) error         { return nil }
func (c blockConn) Do(*pool.Message) (*pool.Message, error)  { return nil, nil }
func (c blockConn) DoObserve(*pool.Message, func(*pool.Message)) (mux.Observation, error) {
	return nil, nil
}
func (c blockConn) Close() error          { return nil }
func (c blockConn) Sequence() uint64      { return 0 }
func (c blockConn) Done() <-chan struct{} { return nil }
func (c blockConn) AddOnClose(func())     {}
func (c blockConn) NewGetRequest(context.Context, string, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) NewObserveRequest(context.Context, string, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) NewPutRequest(context.Context, string, message.MediaType, io.ReadSeeker, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) NewPostRequest(context.Context, string, message.MediaType, io.ReadSeeker, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
func (c blockConn) NewDeleteRequest(context.Context, string, ...message.Option) (*pool.Message, error) {
	return nil, nil
}
