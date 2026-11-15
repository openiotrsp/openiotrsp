package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestTruncateCIPKIdentifier(t *testing.T) {
	t.Parallel()

	one := [][]byte{{0x81, 0x37, 0x0f}}
	two := [][]byte{{0x01, 0x02, 0x03, 0x04}, {0x01, 0x02, 0x05, 0x06}}
	prefix, err := truncateCIPKIdentifier([]byte{0xaa}, one)
	if err != nil || len(prefix) != 0 {
		t.Fatalf("single entry prefix = %x err %v, want empty", prefix, err)
	}
	prefix, err = truncateCIPKIdentifier([]byte{0x01, 0x02, 0x03, 0x04}, two)
	if err != nil || !bytes.Equal(prefix, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("prefix = %x err %v, want 010203", prefix, err)
	}
	if _, err := truncateCIPKIdentifier([]byte{0xff}, two); err == nil {
		t.Fatal("identifier outside the list was truncated")
	}
}

func TestInitiateAuthenticationMinimizesForKigenCapabilities(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(0x41))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := mustRelayHex(t, "33333333333333333333333333333333")
	info1 := sampleEUICCInfo1(t)
	info1Bytes, err := info1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:             eidKey,
		EUICCInfo1:      info1Bytes,
		IPACapabilities: sampleIPACapabilities(t, 0xcc),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	enqueueActivation(t, ctx, store, eidKey, transactionID)
	initOK := mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")
	handler, transport := newInitAuthHandler(t, store, initOK)
	response := handleInitAuth(t, ctx, handler, bytes.Repeat([]byte{0xa5}, 16), transactionID)
	got, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	root, err := parseRelayTLV(got)
	if err != nil {
		t.Fatalf("parse response error = %v", err)
	}
	ok := root.First(bertlv.ContextSpecific.Constructed(0))
	if ok == nil {
		t.Fatalf("response = %x, want A0", got)
	}
	if ok.First(bertlv.ContextSpecific.Primitive(0)) != nil {
		t.Fatalf("minimized OK still has transactionId: %x", got)
	}
	ci := ok.First(tagOctetString)
	if ci == nil || len(ci.Value) != 0 {
		t.Fatalf("euiccCiPKIdentifierToBeUsed = %#v, want 04 00", ci)
	}
	if ok.First(tagInitAuthOKSeq) == nil || ok.First(tagSignature) == nil {
		t.Fatalf("minimized OK dropped signed fields: %x", got)
	}
	session, found := handler.Relay.DownloadContext([]byte{0x01, 0x02, 0x03})
	if !found || !bytes.Equal(session.CIPKID, []byte{0xaa}) {
		t.Fatalf("remembered CI = %x, want aa", session.CIPKID)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("relay calls = %d, want 1", len(transport.calls))
	}
}

func TestAuthenticateClientMinimizesAndChecksMetadata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(0x42))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	eimTx := mustRelayHex(t, "44444444444444444444444444444444")
	info1Bytes, err := sampleEUICCInfo1(t).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	class := int64(1)
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:          eidKey,
		ICCID:        "8910",
		ProfileClass: &class,
	}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:                     eidKey,
		EUICCInfo1:              info1Bytes,
		IPACapabilities:         sampleIPACapabilities(t, 0xcc),
		RulesAuthorisationTable: sampleRAT(t, []byte{0x22, 0xf2, 0x10}, false),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	enqueueActivation(t, ctx, store, eidKey, eimTx)
	txn := []byte{0x01, 0x02, 0x03}
	meta := sampleStoreMetadata(t, false)
	metaBytes, err := meta.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(metadata) error = %v", err)
	}
	authOK := mustAuthOK(t, txn, meta, true)
	transport := &esipaRecordingTransport{responses: map[relay.Endpoint]relay.Response{
		relay.EndpointInitiateAuthentication: {Payload: mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")},
		relay.EndpointAuthenticateClient:     {Payload: authOK},
		relay.EndpointGetBoundProfilePackage: {Payload: mustBoundPackage(t, txn, metaBytes)},
	}}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Logger = discardLogger()
	handler.Relay = relay.New(transport)
	handleInitAuth(t, ctx, handler, bytes.Repeat([]byte{0xa5}, 16), eimTx)

	authResponse := handleTLV(t, ctx, handler, mustAuthRequest(t, txn))
	authRaw, err := EncodeResponse(authResponse)
	if err != nil {
		t.Fatalf("EncodeResponse(auth) error = %v", err)
	}
	authRoot, err := parseRelayTLV(authRaw)
	if err != nil {
		t.Fatalf("parse auth error = %v", err)
	}
	authContainer := authRoot.First(bertlv.ContextSpecific.Constructed(0))
	if authContainer.First(bertlv.ContextSpecific.Primitive(0)) != nil || authContainer.First(tagProfileMetadata) != nil {
		t.Fatalf("AuthenticateClient still exposes transactionId or metadata: %x", authRaw)
	}
	if authContainer.First(tagSignature) == nil {
		t.Fatalf("AuthenticateClient dropped smdpSignature2: %x", authRaw)
	}
	session, ok := handler.Relay.DownloadContext(txn)
	if !ok || !bytes.Equal(session.ProfileMetadata, metaBytes) {
		t.Fatalf("remembered metadata = %x, want %x", session.ProfileMetadata, metaBytes)
	}

	pkgResponse := handleTLV(t, ctx, handler, mustGetBoundRequest(t, txn))
	pkgRaw, err := EncodeResponse(pkgResponse)
	if err != nil {
		t.Fatalf("EncodeResponse(package) error = %v", err)
	}
	pkgRoot, err := parseRelayTLV(pkgRaw)
	if err != nil {
		t.Fatalf("parse package error = %v", err)
	}
	pkgContainer := pkgRoot.First(bertlv.ContextSpecific.Constructed(0))
	if pkgContainer.First(bertlv.ContextSpecific.Primitive(0)) != nil || pkgContainer.First(tagBoundPackage) == nil {
		t.Fatalf("GetBoundProfilePackage = %x, want BPP without transactionId", pkgRaw)
	}
	if !bytes.Contains(pkgRaw, metaBytes) {
		t.Fatalf("GetBoundProfilePackage lost StoreMetadata %x in %x", metaBytes, pkgRaw)
	}

	transport.responses[relay.EndpointGetBoundProfilePackage] = relay.Response{Payload: mustBoundPackage(t, txn, []byte{0xbf, 0x25, 0x00})}
	mismatch := handleTLV(t, ctx, handler, mustGetBoundRequest(t, txn))
	assertIntegerError(t, mismatch, tagGetBoundPackage, getBoundPackageErrorMetadataMismatch)
}

func TestAuthenticateClientRejectsPPRWithoutRAT(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(0x43))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	eimTx := mustRelayHex(t, "55555555555555555555555555555555")
	info1Bytes, err := sampleEUICCInfo1(t).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(EUICCInfo1) error = %v", err)
	}
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:             eidKey,
		EUICCInfo1:      info1Bytes,
		IPACapabilities: sampleIPACapabilities(t, 0xcc),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	enqueueActivation(t, ctx, store, eidKey, eimTx)
	txn := []byte{0x01, 0x02, 0x03}
	transport := &esipaRecordingTransport{responses: map[relay.Endpoint]relay.Response{
		relay.EndpointInitiateAuthentication: {Payload: mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")},
		relay.EndpointAuthenticateClient:     {Payload: mustAuthOK(t, txn, sampleStoreMetadata(t, true), true)},
	}}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Logger = discardLogger()
	handler.Relay = relay.New(transport)
	handleInitAuth(t, ctx, handler, bytes.Repeat([]byte{0xa5}, 16), eimTx)
	response := handleTLV(t, ctx, handler, mustAuthRequest(t, txn))
	assertIntegerError(t, response, tagAuthenticate, authenticateClientErrorPPRNotAllowed)
}

func TestVerifyProfileMetadata(t *testing.T) {
	t.Parallel()

	owner := []byte{0x22, 0xf2, 0x10}
	meta := sampleStoreMetadata(t, true)
	if err := verifyProfileMetadata(meta, nil, nil); err == nil {
		t.Fatal("PPR without a RAT was allowed")
	}
	if err := verifyProfileMetadata(meta, sampleRAT(t, owner, false), nil); err != nil {
		t.Fatalf("matching operator error = %v", err)
	}
	if err := verifyProfileMetadata(meta, sampleRAT(t, []byte{0xee, 0xee, 0xe0}, false), nil); err != nil {
		t.Fatalf("wildcard MCC error = %v", err)
	}
	operational := int64(profileClassOperational)
	if err := verifyProfileMetadata(meta, sampleRAT(t, owner, false), []storage.ProfileState{{ProfileClass: &operational}}); err == nil {
		t.Fatal("PPR1 was allowed beside an operational profile")
	}
	provisioning := int64(1)
	if err := verifyProfileMetadata(meta, sampleRAT(t, owner, false), []storage.ProfileState{{ProfileClass: &provisioning}}); err != nil {
		t.Fatalf("provisioning profile blocked PPR1: %v", err)
	}
	plain := sampleStoreMetadata(t, false)
	if err := verifyProfileMetadata(plain, nil, []storage.ProfileState{{ProfileClass: &operational}}); err != nil {
		t.Fatalf("metadata without PPRs error = %v", err)
	}
}

func newInitAuthHandler(t *testing.T, store storage.Store, initOK []byte) (*Handler, *esipaRecordingTransport) {
	t.Helper()
	transport := &esipaRecordingTransport{responses: map[relay.Endpoint]relay.Response{
		relay.EndpointInitiateAuthentication: {Payload: initOK},
	}}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Logger = discardLogger()
	handler.Relay = relay.New(transport)
	return handler, transport
}

func handleInitAuth(t *testing.T, ctx context.Context, handler *Handler, challenge, transactionID []byte) Response {
	t.Helper()
	return handleTLV(t, ctx, handler, mustMarshalInitAuth(t, challenge, "", nil, transactionID))
}

func handleTLV(t *testing.T, ctx context.Context, handler *Handler, request []byte) Response {
	t.Helper()
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	response, err := handler.handle(ctx, decoded)
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	return response
}

func enqueueActivation(t *testing.T, ctx context.Context, store storage.Store, eid string, transactionID []byte) {
	t.Helper()
	trigger, err := profiledownload.NewActivationCodeTrigger("1$tlt.prod.ondemandconnectivity.com$MATCH", transactionID)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eid, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
}

func sampleStoreMetadata(t *testing.T, withPPR bool) *bertlv.TLV {
	t.Helper()
	children := []*bertlv.TLV{
		bertlv.NewValue(tagEID, bytes.Repeat([]byte{0x89}, 10)),
		bertlv.NewChildren(tagProfileOwner, bertlv.NewChildren(tagSequence,
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x22, 0xf2, 0x10}),
		)),
	}
	if withPPR {
		children = append(children, bertlv.NewValue(tagProfilePolicy, []byte{0x05, 0x40}))
	}
	return bertlv.NewChildren(tagProfileMetadata, children...)
}

func sampleRAT(t *testing.T, mcc []byte, ppr2 bool) []byte {
	t.Helper()
	bits := []byte{0x05, 0x40}
	if ppr2 {
		bits = []byte{0x05, 0x60}
	}
	raw, err := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(6),
		bertlv.NewChildren(tagSequence,
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), bits),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1),
				bertlv.NewChildren(tagSequence,
					bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), mcc),
				),
			),
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x07, 0x00}),
		),
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(RAT) error = %v", err)
	}
	return raw
}

func mustAuthOK(t *testing.T, txn []byte, meta *bertlv.TLV, wrap bool) []byte {
	t.Helper()
	children := []*bertlv.TLV{
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn),
		meta,
		bertlv.NewChildren(tagSequence, bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn)),
		bertlv.NewValue(tagSignature, []byte{0x11, 0x22}),
		bertlv.NewChildren(tagSequence, bertlv.NewValue(tagOctetString, []byte{0xbb})),
	}
	var root *bertlv.TLV
	if wrap {
		root = bertlv.NewChildren(tagAuthenticate, bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0), children...))
	} else {
		root = bertlv.NewChildren(tagAuthenticate, children...)
	}
	raw, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(auth OK) error = %v", err)
	}
	return raw
}

func mustAuthRequest(t *testing.T, txn []byte) []byte {
	t.Helper()
	raw, err := bertlv.NewChildren(tagAuthenticate,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn),
		bertlv.NewChildren(tagAuthenticateServer, bertlv.NewChildren(tagSequence)),
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(auth request) error = %v", err)
	}
	return raw
}

func mustGetBoundRequest(t *testing.T, txn []byte) []byte {
	t.Helper()
	raw, err := bertlv.NewChildren(tagGetBoundPackage,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn),
		bertlv.NewChildren(tagPrepareDownload, bertlv.NewChildren(tagSequence)),
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(get bound request) error = %v", err)
	}
	return raw
}

func mustBoundPackage(t *testing.T, txn, metadata []byte) []byte {
	t.Helper()
	segment := append(append([]byte{}, metadata...), bytes.Repeat([]byte{0xab}, scp03tMACLen)...)
	raw, err := bertlv.NewChildren(tagGetBoundPackage,
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn),
			bertlv.NewChildren(tagBoundPackage,
				bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1),
					bertlv.NewValue(tagSegment88, segment),
				),
			),
		),
	).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(BPP) error = %v", err)
	}
	return raw
}

func assertIntegerError(t *testing.T, response Response, tag bertlv.Tag, want int64) {
	t.Helper()
	raw, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	tlv, err := parseRelayTLV(raw)
	if err != nil {
		t.Fatalf("parse error response error = %v", err)
	}
	if !tlv.Tag.Equal(tag) || len(tlv.Children) != 1 || !tlv.Children[0].Tag.Equal(tagInteger) {
		t.Fatalf("error response = %x, want %s INTEGER", raw, tag)
	}
	var got int64
	if err := tlv.Children[0].UnmarshalValue(primitive.UnmarshalInt(&got)); err != nil {
		t.Fatalf("UnmarshalInt() error = %v", err)
	}
	if got != want {
		t.Fatalf("error = %d, want %d", got, want)
	}
}
