package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestInitiateAuthenticationRestoresAddressAndEUICCInfo1(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x21)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "08563a4fb8847812592e4d4cd2d190c5")
	trigger, err := profiledownload.NewActivationCodeTrigger(
		"1$tlt.prod.ondemandconnectivity.com$MATCH",
		transactionID,
	)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
	info1 := sampleEUICCInfo1(t)
	info1Bytes, err := info1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:        eidKey,
		EUICCInfo1: info1Bytes,
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}

	challenge := bytes.Repeat([]byte{0xa5}, 16)
	request := mustMarshalInitAuth(t, challenge, "", nil, transactionID)
	initOK := mustInitiateAuthOK(t, "tlt.prod.ondemandconnectivity.com")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initOK},
		},
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)

	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("relay calls = %d, want 1", len(transport.calls))
	}
	posted := transport.calls[0].payload
	if transport.calls[0].address != "tlt.prod.ondemandconnectivity.com" {
		t.Fatalf("SM-DP+ address = %q", transport.calls[0].address)
	}
	if bytes.Contains(posted, append([]byte{0x82, 0x10}, transactionID...)) {
		t.Fatalf("posted payload still contains eimTransactionId")
	}
	if !bytes.Contains(posted, []byte("tlt.prod.ondemandconnectivity.com")) {
		t.Fatalf("posted payload missing restored FQDN")
	}
	if !bytes.Contains(posted, info1Bytes) {
		t.Fatalf("posted payload missing restored EUICCInfo1")
	}
	got, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	if !bytes.Equal(got, initOK) {
		t.Fatalf("response = %x, want SM-DP+ OK %x", got, initOK)
	}
}

func TestInitiateAuthenticationUnknownTransactionID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	challenge := bytes.Repeat([]byte{0x11}, 16)
	transactionID := mustRelayHex(t, "ffffffffffffffffffffffffffffffff")
	request := mustMarshalInitAuth(t, challenge, "", nil, transactionID)
	transport := &esipaRecordingTransport{}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)

	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	if len(transport.calls) != 0 {
		t.Fatalf("relay calls = %#v, want none", transport.calls)
	}
	assertInitiateAuthError(t, response, initiateAuthErrorInvalidEimTransactionID)
}

func TestInitiateAuthenticationPassthroughKeepsIPAAddress(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x22)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "0102030405060708090a0b0c0d0e0f10")
	trigger, err := profiledownload.NewActivationCodeTrigger(
		"1$tlt.prod.ondemandconnectivity.com$MATCH",
		transactionID,
	)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}

	challenge := bytes.Repeat([]byte{0x5b}, 16)
	info1 := sampleEUICCInfo1(t)
	ipaAddress := "ipa.supplied.smdp.example"
	request := mustMarshalInitAuth(t, challenge, ipaAddress, info1, transactionID)
	wantES9 := mustMarshalInitAuth(t, challenge, ipaAddress, info1, nil)
	initOK := mustInitiateAuthOK(t, ipaAddress)
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initOK},
		},
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)

	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	if _, err := handler.handle(ctx, decoded); err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("relay calls = %d, want 1", len(transport.calls))
	}
	if transport.calls[0].address != ipaAddress {
		t.Fatalf("SM-DP+ address = %q, want IPA-supplied %q", transport.calls[0].address, ipaAddress)
	}
	if !bytes.Equal(transport.calls[0].payload, wantES9) {
		t.Fatalf("posted payload = %x, want strip-only %x", transport.calls[0].payload, wantES9)
	}
}

func TestInitiateAuthenticationRestoredAddressMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x23)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "aabbccddeeff00112233445566778899")
	trigger, err := profiledownload.NewActivationCodeTrigger(
		"1$tlt.prod.ondemandconnectivity.com$MATCH",
		transactionID,
	)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
	info1 := sampleEUICCInfo1(t)
	info1Bytes, err := info1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:        eidKey,
		EUICCInfo1: info1Bytes,
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}

	challenge := bytes.Repeat([]byte{0x42}, 16)
	request := mustMarshalInitAuth(t, challenge, "", nil, transactionID)
	mismatchOK := mustInitiateAuthOK(t, "other.smdp.example")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: mismatchOK},
		},
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)

	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("relay calls = %d, want 1 SM-DP+ hop before mismatch", len(transport.calls))
	}
	assertInitiateAuthError(t, response, initiateAuthErrorSMDPAddressMismatch)
}

func TestInitiateAuthenticationMissingEUICCInfo1ReturnsDefinedError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x24)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "00112233445566778899aabbccddeeff")
	trigger, err := profiledownload.NewActivationCodeTrigger(
		"1$tlt.prod.ondemandconnectivity.com$MATCH",
		transactionID,
	)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}

	challenge := bytes.Repeat([]byte{0x77}, 16)
	request := mustMarshalInitAuth(t, challenge, "", nil, transactionID)
	transport := &esipaRecordingTransport{}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)

	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	if len(transport.calls) != 0 {
		t.Fatalf("relay calls = %#v, want none before euiccInfo1 is stored", transport.calls)
	}
	assertInitiateAuthError(t, response, initiateAuthErrorUndefined)
}

func sampleEUICCInfo1(t *testing.T) *bertlv.TLV {
	t.Helper()
	return bertlv.NewChildren(tagInitAuthInfo1,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x03, 0x02, 0x03, 0x00}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xaa, 0x01}),
		),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(10),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xbb, 0x02}),
		),
	)
}

func mustMarshalInitAuth(t *testing.T, challenge []byte, address string, info1 *bertlv.TLV, transactionID []byte) []byte {
	t.Helper()
	children := []*bertlv.TLV{
		bertlv.NewValue(tagInitAuthChallenge, challenge),
	}
	if address != "" {
		children = append(children, bertlv.NewValue(tagInitAuthAddress, []byte(address)))
	}
	if info1 != nil {
		children = append(children, info1.Clone())
	}
	if len(transactionID) > 0 {
		children = append(children, bertlv.NewValue(tagInitAuthTxn, transactionID))
	}
	raw, err := bertlv.NewChildren(tagInitiateAuth, children...).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(InitAuth) error = %v", err)
	}
	return raw
}

func mustInitiateAuthOK(t *testing.T, serverAddress string) []byte {
	t.Helper()
	signed1 := bertlv.NewChildren(tagInitAuthOKSeq,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x01, 0x02, 0x03}),
		bertlv.NewValue(tagServerAddress, []byte(serverAddress)),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), bytes.Repeat([]byte{0xcc}, 16)),
	)
	raw, err := bertlv.NewChildren(tagInitiateAuth,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x01, 0x02, 0x03}),
		signed1,
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(InitAuth OK) error = %v", err)
	}
	return raw
}

func TestInitiateAuthenticationAppendsMatchingIDAndCtxParams1(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(0x31))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "0de53453f9c98a9c788c12ea316d8bc6")
	const matchingID = "MATCHTOK"
	trigger, err := profiledownload.NewActivationCodeTrigger(
		"1$tlt.prod.ondemandconnectivity.com$"+matchingID,
		transactionID,
	)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
	info1 := sampleEUICCInfo1(t)
	info1Bytes, err := info1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	device := sampleDeviceInfo(t)
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:             eidKey,
		EUICCInfo1:      info1Bytes,
		IPACapabilities: sampleIPACapabilities(t, 0xf0),
		DeviceInfo:      device,
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}

	challenge := bytes.Repeat([]byte{0xa5}, 16)
	request := mustMarshalInitAuth(t, challenge, "", nil, transactionID)
	initOK := mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initOK},
		},
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("relay calls = %d, want 1", len(transport.calls))
	}
	posted := transport.calls[0].payload
	if bytes.Contains(posted, []byte(matchingID)) {
		t.Fatalf("SM-DP+ request contains matchingId")
	}
	if !bytes.Contains(posted, info1Bytes) || !bytes.Contains(posted, []byte("tlt.prod.ondemandconnectivity.com")) {
		t.Fatalf("SM-DP+ request = %x, want restored address and EUICCInfo1", posted)
	}
	got, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	want := mustAppendCtxParams(t, initOK, matchingID, device)
	if !bytes.Equal(got, want) {
		t.Fatalf("response = %x\nwant     %x", got, want)
	}
	session, ok := handler.Relay.DownloadContext([]byte{0x01, 0x02, 0x03})
	if !ok {
		t.Fatal("download session was not remembered")
	}
	if string(session.ServerAddress) != "tlt.prod.ondemandconnectivity.com" || len(session.ServerChallenge) != 16 || len(session.CtxParams1) == 0 {
		t.Fatalf("download session = %#v, want serverSigned1 fields and ctxParams1", session)
	}
}

func TestInitiateAuthenticationWithoutEIMDataBitsPassesThrough(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(0x32))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "11111111111111111111111111111111")
	trigger, err := profiledownload.NewActivationCodeTrigger(
		"1$tlt.prod.ondemandconnectivity.com$MATCHTOK",
		transactionID,
	)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
	info1 := sampleEUICCInfo1(t)
	info1Bytes, err := info1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:             eidKey,
		EUICCInfo1:      info1Bytes,
		IPACapabilities: sampleIPACapabilities(t, 0xc0),
		DeviceInfo:      sampleDeviceInfo(t),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	request := mustMarshalInitAuth(t, bytes.Repeat([]byte{0xa5}, 16), "", nil, transactionID)
	initOK := mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initOK},
		},
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	got, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	if !bytes.Equal(got, initOK) {
		t.Fatalf("response = %x, want unchanged SM-DP+ OK %x", got, initOK)
	}
}

func TestInitiateAuthenticationCtxParams1MissingDeviceInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(0x33))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "22222222222222222222222222222222")
	trigger, err := profiledownload.NewActivationCodeTrigger(
		"1$tlt.prod.ondemandconnectivity.com$MATCHTOK",
		transactionID,
	)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
	info1 := sampleEUICCInfo1(t)
	info1Bytes, err := info1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:             eidKey,
		EUICCInfo1:      info1Bytes,
		IPACapabilities: sampleIPACapabilities(t, 0xf4),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	request := mustMarshalInitAuth(t, bytes.Repeat([]byte{0xa5}, 16), "", nil, transactionID)
	initOK := mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initOK},
		},
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Logger = discardLogger()
	handler.Relay = relay.New(transport)
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("relay calls = %d, want the SM-DP+ hop before the eIM error", len(transport.calls))
	}
	assertInitiateAuthError(t, response, initiateAuthErrorUndefined)
}

func sampleDeviceInfo(t *testing.T) []byte {
	t.Helper()
	raw, err := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x35, 0x32, 0x30, 0x31}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1)),
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(deviceInfo) error = %v", err)
	}
	return raw
}

func sampleIPACapabilities(t *testing.T, features byte) []byte {
	t.Helper()
	raw, err := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(8),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x02, features}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte{0x07, 0x80}),
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(IPACapabilities) error = %v", err)
	}
	return raw
}

func mustInitiateAuthOKWrapped(t *testing.T, serverAddress string) []byte {
	t.Helper()
	signed1 := bertlv.NewChildren(tagInitAuthOKSeq,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x01, 0x02, 0x03}),
		bertlv.NewValue(tagServerAddress, []byte(serverAddress)),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), bytes.Repeat([]byte{0xcc}, 16)),
	)
	raw, err := bertlv.NewChildren(tagInitiateAuth,
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x01, 0x02, 0x03}),
			signed1,
			bertlv.NewValue(bertlv.Application.Primitive(55), []byte{0x11, 0x22}),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xaa}),
			bertlv.NewChildren(tagInitAuthOKSeq, bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xbb})),
		),
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(InitAuth OK) error = %v", err)
	}
	return raw
}

func mustAppendCtxParams(t *testing.T, ok []byte, matchingID string, deviceInfo []byte) []byte {
	t.Helper()
	root, err := parseRelayTLV(ok)
	if err != nil {
		t.Fatalf("parse OK error = %v", err)
	}
	device, err := parseRelayTLV(deviceInfo)
	if err != nil {
		t.Fatalf("parse deviceInfo error = %v", err)
	}
	device.Tag = bertlv.ContextSpecific.Constructed(1)
	choice := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte(matchingID)),
		device,
	)
	container := root.First(bertlv.ContextSpecific.Constructed(0))
	container.Children = append(container.Children,
		bertlv.NewValue(bertlv.Universal.Primitive(12), []byte(matchingID)),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2), choice),
	)
	raw, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(expected OK) error = %v", err)
	}
	return raw
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func assertInitiateAuthError(t *testing.T, response Response, want int64) {
	t.Helper()
	raw, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	tlv, err := parseRelayTLV(raw)
	if err != nil {
		t.Fatalf("parse response error = %v", err)
	}
	if !tlv.Tag.Equal(tagInitiateAuth) {
		t.Fatalf("response tag = %s, want bf39", tlv.Tag)
	}
	if len(tlv.Children) != 1 || !tlv.Children[0].Tag.Equal(tagInteger) {
		t.Fatalf("response children = %#v, want one INTEGER", tlv.Children)
	}
	var got int64
	if err := tlv.Children[0].UnmarshalValue(primitive.UnmarshalInt(&got)); err != nil {
		t.Fatalf("UnmarshalInt() error = %v", err)
	}
	if got != want {
		t.Fatalf("initiateAuthenticationError = %d, want %d", got, want)
	}
}
