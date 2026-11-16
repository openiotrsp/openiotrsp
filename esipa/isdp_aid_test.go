package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestBoundPackageCleartextISDPAIDRestoresCompactSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	meta := sampleStoreMetadata(t, false)
	handler, transport := setupIndirectDownload(t, 0xcc, meta)
	txn := []byte{0x01, 0x02, 0x03}
	session, ok := handler.Relay.DownloadContext(txn)
	if !ok || len(session.ISDPAID) != 0 {
		t.Fatalf("ISD-P AID after AuthenticateClient = %x, want empty", session.ISDPAID)
	}

	aid := []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x34}
	// The 87 value starts with tag 4F. It is encrypted, so it must not become the session AID.
	decoy := append([]byte{0x4f, 0x10}, bytes.Repeat([]byte{0xee}, 16)...)
	metaBytes := marshalTLV(t, meta)
	segment := append(append([]byte{}, metaBytes...), bytes.Repeat([]byte{0xab}, scp03tMACLen)...)
	bpp := longFormTLV(tagBoundPackage, joinBytes(
		marshalTLV(t, bertlv.NewValue(tagSegment87, decoy)),
		marshalTLV(t, bertlv.NewValue(tagSegment88, segment)),
		marshalTLV(t, bertlv.NewValue(tagISDPAID, aid)),
	))
	if len(bpp) < 3 || bpp[2] != 0x82 {
		t.Fatalf("fixture BF36 = %x, want a long-form length", bpp)
	}
	txnTLV := marshalTLV(t, bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn))
	payload := mustRawSuccess(t, tagGetBoundPackage, true, txnTLV, bpp)
	transport.responses[relay.EndpointGetBoundProfilePackage] = relay.Response{Payload: payload}

	response := handleTLV(t, ctx, handler, mustGetBoundRequest(t, txn))
	got, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	if !bytes.Equal(got, mustRawSuccess(t, tagGetBoundPackage, true, bpp)) {
		t.Fatalf("GetBoundProfilePackage rewrote BF36\n got %x\nwant original BF36", got)
	}
	session, ok = handler.Relay.DownloadContext(txn)
	if !ok || !bytes.Equal(session.ISDPAID, aid) {
		t.Fatalf("ISD-P AID = %x, want %x", session.ISDPAID, aid)
	}

	before := notificationCalls(transport)
	handleTLV(t, ctx, handler, compactInstall(t, txn, compactSuccess(compactAidOf(aid))))
	if notificationCalls(transport) != before+1 {
		t.Fatal("ES9+ HandleNotification was not called for the restored AID")
	}
	posted := lastNotification(t, transport)
	restored := findTLV(parseTLV(t, posted), tagISDPAID)
	if restored == nil || !bytes.Equal(restored.Value, aid) {
		t.Fatalf("SuccessResult.aid = %v, want %x", restored, aid)
	}
	if !bytes.Contains(posted, defaultSimaResponse) {
		t.Fatalf("rebuilt notification missing default simaResponse: %x", posted)
	}

	rejected := handleTLV(t, ctx, handler, compactInstall(t, txn, compactSuccess([]byte{0x00, 0x00})))
	assertIntegerError(t, rejected, tagHandleNotify, initiateAuthErrorUndefined)
	if notificationCalls(transport) != before+1 {
		t.Fatal("ES9+ HandleNotification was called for a compactAid that is not bytes 14 and 15")
	}
}

func TestMetadataISDPAIDIsKeptWhenBoundPackageHasAnother(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fromMetadata := []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11}
	meta := bertlv.NewChildren(tagProfileMetadata,
		bertlv.NewValue(tagEID, bytes.Repeat([]byte{0x89}, 10)),
		bertlv.NewValue(tagISDPAID, fromMetadata),
	)
	handler, transport := setupIndirectDownload(t, 0xcc, meta)
	txn := []byte{0x01, 0x02, 0x03}
	session, ok := handler.Relay.DownloadContext(txn)
	if !ok || !bytes.Equal(session.ISDPAID, fromMetadata) {
		t.Fatalf("AID from metadata = %x, want %x", session.ISDPAID, fromMetadata)
	}

	other := []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22}
	metaBytes := marshalTLV(t, meta)
	segment := append(append([]byte{}, metaBytes...), bytes.Repeat([]byte{0xab}, scp03tMACLen)...)
	bpp := longFormTLV(tagBoundPackage, joinBytes(
		marshalTLV(t, bertlv.NewValue(tagSegment88, segment)),
		marshalTLV(t, bertlv.NewValue(tagISDPAID, other)),
	))
	txnTLV := marshalTLV(t, bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn))
	transport.responses[relay.EndpointGetBoundProfilePackage] = relay.Response{
		Payload: mustRawSuccess(t, tagGetBoundPackage, true, txnTLV, bpp),
	}
	response := handleTLV(t, ctx, handler, mustGetBoundRequest(t, txn))
	got, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	if !bytes.Contains(got, bpp) {
		t.Fatal("GetBoundProfilePackage did not keep the original BF36")
	}
	session, ok = handler.Relay.DownloadContext(txn)
	if !ok || !bytes.Equal(session.ISDPAID, fromMetadata) {
		t.Fatalf("AID after bound package = %x, want the metadata AID %x", session.ISDPAID, fromMetadata)
	}

	before := notificationCalls(transport)
	handleTLV(t, ctx, handler, compactInstall(t, txn, compactSuccess(compactAidOf(fromMetadata))))
	if notificationCalls(transport) != before+1 {
		t.Fatal("ES9+ HandleNotification was not called for the metadata AID")
	}
	posted := lastNotification(t, transport)
	restored := findTLV(parseTLV(t, posted), tagISDPAID)
	if restored == nil || !bytes.Equal(restored.Value, fromMetadata) {
		t.Fatalf("SuccessResult.aid = %v, want %x", restored, fromMetadata)
	}
	rejected := handleTLV(t, ctx, handler, compactInstall(t, txn, compactSuccess(compactAidOf(other))))
	assertIntegerError(t, rejected, tagHandleNotify, initiateAuthErrorUndefined)
	if notificationCalls(transport) != before+1 {
		t.Fatal("ES9+ HandleNotification was called for the other AID")
	}
}

func TestCompactSuccessRebuildsGSMAISDPAID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	meta := sampleStoreMetadata(t, false)
	handler, transport := setupIndirectDownload(t, 0xcc, meta)
	txn := []byte{0x01, 0x02, 0x03}
	session, ok := handler.Relay.DownloadContext(txn)
	if !ok || len(session.ISDPAID) != 0 {
		t.Fatalf("ISD-P AID after AuthenticateClient = %x, want empty", session.ISDPAID)
	}

	metaBytes := marshalTLV(t, meta)
	segment := append(append([]byte{}, metaBytes...), bytes.Repeat([]byte{0xab}, scp03tMACLen)...)
	bpp := longFormTLV(tagBoundPackage, marshalTLV(t, bertlv.NewValue(tagSegment88, segment)))
	txnTLV := marshalTLV(t, bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn))
	payload := mustRawSuccess(t, tagGetBoundPackage, true, txnTLV, bpp)
	transport.responses[relay.EndpointGetBoundProfilePackage] = relay.Response{Payload: payload}

	response := handleTLV(t, ctx, handler, mustGetBoundRequest(t, txn))
	got, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	if !bytes.Equal(got, mustRawSuccess(t, tagGetBoundPackage, true, bpp)) {
		t.Fatalf("GetBoundProfilePackage rewrote BF36\n got %x\nwant original BF36", got)
	}
	session, ok = handler.Relay.DownloadContext(txn)
	if !ok || len(session.ISDPAID) != 0 {
		t.Fatalf("ISD-P AID after bound package = %x, want empty", session.ISDPAID)
	}

	want := []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0x89, 0x00, 0x00, 0x14, 0x00}
	before := notificationCalls(transport)
	handleTLV(t, ctx, handler, compactInstall(t, txn, compactSuccess([]byte{0x00, 0x14})))
	if notificationCalls(transport) != before+1 {
		t.Fatal("ES9+ HandleNotification was not called for the rebuilt AID")
	}
	posted := lastNotification(t, transport)
	restored := findTLV(parseTLV(t, posted), tagISDPAID)
	if restored == nil || !bytes.Equal(restored.Value, want) {
		t.Fatalf("SuccessResult.aid = %v, want %x", restored, want)
	}
	if !bytes.Contains(posted, defaultSimaResponse) {
		t.Fatalf("rebuilt notification missing default simaResponse: %x", posted)
	}
	session, ok = handler.Relay.DownloadContext(txn)
	if !ok || !bytes.Equal(session.ISDPAID, want) {
		t.Fatalf("download session AID = %x, want %x", session.ISDPAID, want)
	}
}

func TestStoredISDPAIDMatchesBytes14And15(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	aid := []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0x89, 0x00, 0x00, 0x14, 0x00}
	meta := bertlv.NewChildren(tagProfileMetadata,
		bertlv.NewValue(tagEID, bytes.Repeat([]byte{0x89}, 10)),
		bertlv.NewValue(tagISDPAID, aid),
	)
	handler, transport := setupIndirectDownload(t, 0xcc, meta)
	txn := []byte{0x01, 0x02, 0x03}
	session, ok := handler.Relay.DownloadContext(txn)
	if !ok || !bytes.Equal(session.ISDPAID, aid) {
		t.Fatalf("ISD-P AID = %x, want %x", session.ISDPAID, aid)
	}

	before := notificationCalls(transport)
	handleTLV(t, ctx, handler, compactInstall(t, txn, compactSuccess([]byte{0x00, 0x14})))
	if notificationCalls(transport) != before+1 {
		t.Fatal("ES9+ HandleNotification was not called for compactAid 0014")
	}
	posted := lastNotification(t, transport)
	restored := findTLV(parseTLV(t, posted), tagISDPAID)
	if restored == nil || !bytes.Equal(restored.Value, aid) {
		t.Fatalf("SuccessResult.aid = %v, want %x", restored, aid)
	}

	rejected := handleTLV(t, ctx, handler, compactInstall(t, txn, compactSuccess([]byte{0x14, 0x00})))
	assertIntegerError(t, rejected, tagHandleNotify, initiateAuthErrorUndefined)
	if notificationCalls(transport) != before+1 {
		t.Fatal("ES9+ HandleNotification was called for the last two AID octets")
	}
}

func TestCompactNotificationWithoutCleartextAID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	handler, transport := setupIndirectDownload(t, 0xcc, sampleStoreMetadata(t, false))
	txn := []byte{0x01, 0x02, 0x03}
	before := notificationCalls(transport)

	handleTLV(t, ctx, handler, compactInstall(t, txn, compactErrorResult()))
	if notificationCalls(transport) != before+1 {
		t.Fatal("compact errorResult was not forwarded")
	}
	posted := lastNotification(t, transport)
	if findTLV(parseTLV(t, posted), tagISDPAID) != nil {
		t.Fatalf("errorResult gained an AID: %x", posted)
	}
	if !bytes.Contains(posted, []byte{0x02, 0x01, 0x09}) {
		t.Fatalf("errorResult = %x, want errorReason 9", posted)
	}

	full := marshalTLV(t, bertlv.NewChildren(tagHandleNotify,
		bertlv.NewChildren(tagProfileInstall,
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn),
			bertlv.NewValue(tagOctetString, []byte{0xaa, 0xbb}),
		),
	))
	handleTLV(t, ctx, handler, full)
	if !bytes.Equal(lastNotification(t, transport), full) {
		t.Fatal("full ProfileInstallationResult was rewritten")
	}
}

func setupIndirectDownload(t *testing.T, features byte, meta *bertlv.TLV) (*Handler, *esipaRecordingTransport) {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	eidKey := hex.EncodeToString(testEID(features))
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
		IPACapabilities: sampleIPACapabilities(t, features),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	eimTx := bytes.Repeat([]byte{features ^ 0x5a}, 16)
	enqueueActivation(t, ctx, store, eidKey, eimTx)
	transport := &esipaRecordingTransport{responses: map[relay.Endpoint]relay.Response{
		relay.EndpointInitiateAuthentication: {Payload: mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")},
		relay.EndpointAuthenticateClient:     {Payload: mustAuthOK(t, []byte{0x01, 0x02, 0x03}, meta, true)},
		relay.EndpointHandleNotification:     {NoContent: true},
	}}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Logger = discardLogger()
	handler.Relay = relay.New(transport)
	handleInitAuth(t, ctx, handler, bytes.Repeat([]byte{0xa5}, 16), eimTx)
	handleTLV(t, ctx, handler, mustAuthRequest(t, []byte{0x01, 0x02, 0x03}))
	return handler, transport
}

func compactInstall(t *testing.T, txn []byte, final *bertlv.TLV) []byte {
	t.Helper()
	seq, err := bertlv.MarshalValue(bertlv.Universal.Primitive(2), primitive.MarshalInt(9))
	if err != nil {
		t.Fatalf("MarshalValue(seq) error = %v", err)
	}
	return marshalTLV(t, bertlv.NewChildren(tagHandleNotify,
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
				bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn),
				seq,
				final,
			),
			bertlv.NewValue(tagSignature, []byte{0x01}),
		),
	))
}

// compactAidOf is bytes 14 and 15 of an ISD-P AID, counted from 1.
func compactAidOf(aid []byte) []byte {
	return aid[13:15]
}

func compactSuccess(suffix []byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
			bertlv.NewValue(tagISDPAID, suffix),
		),
	)
}

func compactErrorResult() *bertlv.TLV {
	command, err := bertlv.MarshalValue(bertlv.Universal.Primitive(2), primitive.MarshalInt(1))
	if err != nil {
		panic(err)
	}
	reason, err := bertlv.MarshalValue(bertlv.Universal.Primitive(2), primitive.MarshalInt(9))
	if err != nil {
		panic(err)
	}
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1), command, reason),
	)
}

func notificationCalls(transport *esipaRecordingTransport) int {
	n := 0
	for _, call := range transport.calls {
		if call.endpoint == relay.EndpointHandleNotification {
			n++
		}
	}
	return n
}

func lastNotification(t *testing.T, transport *esipaRecordingTransport) []byte {
	t.Helper()
	for i := len(transport.calls) - 1; i >= 0; i-- {
		if transport.calls[i].endpoint == relay.EndpointHandleNotification {
			return transport.calls[i].payload
		}
	}
	t.Fatal("ES9+ HandleNotification was not called")
	return nil
}

func parseTLV(t *testing.T, payload []byte) *bertlv.TLV {
	t.Helper()
	tlv, err := parseRelayTLV(payload)
	if err != nil {
		t.Fatalf("parse TLV error = %v", err)
	}
	return tlv
}

func findTLV(tlv *bertlv.TLV, tag bertlv.Tag) *bertlv.TLV {
	if tlv == nil {
		return nil
	}
	if tlv.Tag.Equal(tag) {
		return tlv
	}
	for _, child := range tlv.Children {
		if found := findTLV(child, tag); found != nil {
			return found
		}
	}
	return nil
}
