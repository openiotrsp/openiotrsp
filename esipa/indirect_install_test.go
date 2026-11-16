package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

// smdpTransactionID is the transactionId inside mustInitiateAuthOKWrapped.
var smdpTransactionID = []byte{0x01, 0x02, 0x03}

func TestIndirectInstallationResultClosesRememberedTrigger(t *testing.T) {
	t.Parallel()

	t.Run("compact success", func(t *testing.T) {
		t.Parallel()
		fx := startIndirectDownload(t, 0x21, bytes.Repeat([]byte{0x21}, 16))
		before := notificationCalls(fx.transport)
		response := handleTLV(t, fx.ctx, fx.handler, compactInstall(t, fx.smdpTx, compactSuccess(compactAidOf(fx.aid))))
		assertEmptyNotification(t, response)
		if notificationCalls(fx.transport) != before+1 {
			t.Fatal("ES9+ HandleNotification was not called")
		}
		posted := lastNotification(t, fx.transport)
		if bytes.Contains(posted, fx.eimTx) {
			t.Fatalf("ES9+ payload contains eimTransactionId %x", fx.eimTx)
		}
		if !bytes.Contains(posted, []byte{0xbf, 0x37}) {
			t.Fatalf("ES9+ payload = %x, want the rebuilt BF37", posted)
		}
		assertTriggerResult(t, fx, storage.OperationDone, true)
		assertNoEimPackage(t, fx)
		assertNoProfiles(t, fx)
	})

	t.Run("compact error", func(t *testing.T) {
		t.Parallel()
		fx := startIndirectDownload(t, 0x22, bytes.Repeat([]byte{0x22}, 16))
		response := handleTLV(t, fx.ctx, fx.handler, compactInstall(t, fx.smdpTx, compactErrorResult()))
		assertEmptyNotification(t, response)
		assertTriggerResult(t, fx, storage.OperationFailed, false)
		assertNoEimPackage(t, fx)
		assertNoProfiles(t, fx)
	})

	t.Run("smdp rejects", func(t *testing.T) {
		t.Parallel()
		fx := startIndirectDownload(t, 0x23, bytes.Repeat([]byte{0x23}, 16))
		fx.transport.fail = map[relay.Endpoint]error{
			relay.EndpointHandleNotification: errors.New("smdp rejected notification"),
		}
		before := notificationCalls(fx.transport)
		_, err := handleRequest(t, fx, compactInstall(t, fx.smdpTx, compactSuccess(compactAidOf(fx.aid))))
		if err == nil {
			t.Fatal("HandleNotification error = nil, want the SM-DP+ rejection")
		}
		if notificationCalls(fx.transport) != before+1 {
			t.Fatal("ES9+ HandleNotification was not called")
		}
		assertStillPending(t, fx)
	})

	t.Run("compact cannot be rebuilt", func(t *testing.T) {
		t.Parallel()
		fx := startIndirectDownload(t, 0x24, bytes.Repeat([]byte{0x24}, 16))
		before := notificationCalls(fx.transport)
		rejected := handleTLV(t, fx.ctx, fx.handler, compactInstall(t, fx.smdpTx, compactSuccess([]byte{0x00, 0x00})))
		assertIntegerError(t, rejected, tagHandleNotify, initiateAuthErrorUndefined)
		if notificationCalls(fx.transport) != before {
			t.Fatal("ES9+ HandleNotification was called for a compact result that cannot be rebuilt")
		}
		assertStillPending(t, fx)
	})

	t.Run("no download session", func(t *testing.T) {
		t.Parallel()
		fx := startIndirectDownload(t, 0x25, bytes.Repeat([]byte{0x25}, 16))
		before := notificationCalls(fx.transport)
		rejected := handleTLV(t, fx.ctx, fx.handler, compactInstall(t, []byte{0x99, 0x88, 0x77}, compactErrorResult()))
		assertIntegerError(t, rejected, tagHandleNotify, initiateAuthErrorUndefined)
		if notificationCalls(fx.transport) != before {
			t.Fatal("ES9+ HandleNotification was called without a download session")
		}
		assertStillPending(t, fx)
	})

	t.Run("other signed notification", func(t *testing.T) {
		t.Parallel()
		fx := startIndirectDownload(t, 0x26, bytes.Repeat([]byte{0x26}, 16))
		before := notificationCalls(fx.transport)
		notice := marshalTLV(t, bertlv.NewChildren(tagHandleNotify, samplePendingNotification(t, fx.eid, 7, "enable")))
		response := handleTLV(t, fx.ctx, fx.handler, notice)
		assertEmptyNotification(t, response)
		if notificationCalls(fx.transport) != before+1 {
			t.Fatal("OtherSignedNotification was not forwarded")
		}
		if !bytes.Equal(lastNotification(t, fx.transport), notice) {
			t.Fatal("OtherSignedNotification was rewritten")
		}
		assertStillPending(t, fx)
	})

	t.Run("two pending triggers", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		store := memory.New()
		eid := testEID(0x27)
		eidKey := hex.EncodeToString(eid)
		registerIndirectEUICC(t, ctx, store, eidKey)
		otherTx := bytes.Repeat([]byte{0x71}, 16)
		other, err := enqueueIndirectTrigger(t, ctx, store, eidKey, otherTx)
		if err != nil {
			t.Fatal(err)
		}
		matchedTx := bytes.Repeat([]byte{0x27}, 16)
		fx := connectIndirectDownload(t, ctx, store, eid, eidKey, matchedTx)
		handleTLV(t, fx.ctx, fx.handler, compactInstall(t, fx.smdpTx, compactSuccess(compactAidOf(fx.aid))))
		assertRecordedTrigger(t, fx, storage.OperationDone, true)
		pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 10)
		if err != nil {
			t.Fatalf("FetchPendingOperations() error = %v", err)
		}
		if len(pending) != 1 || pending[0].ID != other.ID {
			t.Fatalf("pending = %#v, want only trigger %d", pending, other.ID)
		}
		if _, err := store.GetOperationResult(ctx, storage.DefaultTenantID, other.ID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("other trigger result error = %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("session without eimTransactionId", func(t *testing.T) {
		t.Parallel()
		fx := startIndirectDownload(t, 0x28, bytes.Repeat([]byte{0x28}, 16))
		fx.handler.Relay.UpdateDownload(fx.smdpTx, func(ctx *relay.DownloadContext) {
			ctx.EimTransactionID = nil
		})
		before := notificationCalls(fx.transport)
		response := handleTLV(t, fx.ctx, fx.handler, compactInstall(t, fx.smdpTx, compactSuccess(compactAidOf(fx.aid))))
		assertEmptyNotification(t, response)
		if notificationCalls(fx.transport) != before+1 {
			t.Fatal("installation result was not forwarded")
		}
		assertStillPending(t, fx)
	})

	t.Run("full profile installation result", func(t *testing.T) {
		t.Parallel()
		for _, pending := range []bool{true, false} {
			fx := startIndirectDownload(t, 0x29, bytes.Repeat([]byte{0x29}, 16))
			notice := fullInstallationNotification(t, fx.smdpTx, pending)
			response := handleTLV(t, fx.ctx, fx.handler, notice)
			assertEmptyNotification(t, response)
			if !bytes.Equal(lastNotification(t, fx.transport), notice) {
				t.Fatal("full ProfileInstallationResult was rewritten")
			}
			assertTriggerResult(t, fx, storage.OperationDone, true)
			assertNoEimPackage(t, fx)
		}
	})
}

type indirectDownload struct {
	ctx       context.Context
	store     storage.Store
	handler   *Handler
	transport *esipaRecordingTransport
	eid       []byte
	eidKey    string
	eimTx     []byte
	smdpTx    []byte
	aid       []byte
	operation storage.Operation
}

func startIndirectDownload(t *testing.T, last byte, eimTx []byte) indirectDownload {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	eid := testEID(last)
	eidKey := hex.EncodeToString(eid)
	registerIndirectEUICC(t, ctx, store, eidKey)
	return connectIndirectDownload(t, ctx, store, eid, eidKey, eimTx)
}

func registerIndirectEUICC(t *testing.T, ctx context.Context, store storage.Store, eidKey string) {
	t.Helper()
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
		IPACapabilities: sampleIPACapabilities(t, 0),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
}

func connectIndirectDownload(t *testing.T, ctx context.Context, store storage.Store, eid []byte, eidKey string, eimTx []byte) indirectDownload {
	t.Helper()
	operation, err := enqueueIndirectTrigger(t, ctx, store, eidKey, eimTx)
	if err != nil {
		t.Fatal(err)
	}
	aid := []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x34}
	meta := bertlv.NewChildren(tagProfileMetadata,
		bertlv.NewValue(tagEID, bytes.Repeat([]byte{0x89}, 10)),
		bertlv.NewValue(tagISDPAID, aid),
	)
	transport := &esipaRecordingTransport{responses: map[relay.Endpoint]relay.Response{
		relay.EndpointInitiateAuthentication: {Payload: mustInitiateAuthOKWrapped(t, "tlt.prod.ondemandconnectivity.com")},
		relay.EndpointAuthenticateClient:     {Payload: mustAuthOK(t, smdpTransactionID, meta, true)},
		relay.EndpointHandleNotification:     {NoContent: true},
	}}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Logger = discardLogger()
	handler.Relay = relay.New(transport)
	handleInitAuth(t, ctx, handler, bytes.Repeat([]byte{0xa5}, 16), eimTx)
	handleTLV(t, ctx, handler, mustAuthRequest(t, smdpTransactionID))
	session, ok := handler.Relay.DownloadContext(smdpTransactionID)
	if !ok || !bytes.Equal(session.EimTransactionID, eimTx) {
		t.Fatalf("download eimTransactionId = %x, want %x", session.EimTransactionID, eimTx)
	}
	return indirectDownload{
		ctx:       ctx,
		store:     store,
		handler:   handler,
		transport: transport,
		eid:       eid,
		eidKey:    eidKey,
		eimTx:     append([]byte(nil), eimTx...),
		smdpTx:    append([]byte(nil), smdpTransactionID...),
		aid:       aid,
		operation: operation,
	}
}

func enqueueIndirectTrigger(t *testing.T, ctx context.Context, store storage.Store, eidKey string, eimTx []byte) (storage.Operation, error) {
	t.Helper()
	trigger, err := profiledownload.NewActivationCodeTrigger("1$tlt.prod.ondemandconnectivity.com$MATCH", eimTx)
	if err != nil {
		return storage.Operation{}, err
	}
	return profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger)
}

func fullInstallationNotification(t *testing.T, txn []byte, pending bool) []byte {
	t.Helper()
	installation := bertlv.NewChildren(tagProfileInstall,
		bertlv.NewChildren(tagInstallData,
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), txn),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
				bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0)),
			),
		),
		bertlv.NewValue(tagSignature, []byte{0x01}),
	)
	body := installation
	if pending {
		body = bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0), installation)
	}
	return marshalTLV(t, bertlv.NewChildren(tagHandleNotify, body))
}

func handleRequest(t *testing.T, fx indirectDownload, request []byte) (Response, error) {
	t.Helper()
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	return fx.handler.handle(fx.ctx, decoded)
}

func assertEmptyNotification(t *testing.T, response Response) {
	t.Helper()
	if response.Raw != nil || response.Message.Raw != nil {
		raw, _ := EncodeResponse(response)
		t.Fatalf("IPA response = %x, want an empty 204", raw)
	}
}

func assertTriggerResult(t *testing.T, fx indirectDownload, status storage.OperationStatus, succeeded bool) {
	t.Helper()
	assertRecordedTrigger(t, fx, status, succeeded)
	pending, err := fx.store.FetchPendingOperations(fx.ctx, storage.DefaultTenantID, fx.eidKey, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %#v, want the trigger to have left the queue", pending)
	}
}

func assertRecordedTrigger(t *testing.T, fx indirectDownload, status storage.OperationStatus, succeeded bool) {
	t.Helper()
	result, err := fx.store.GetOperationResult(fx.ctx, storage.DefaultTenantID, fx.operation.ID)
	if err != nil {
		t.Fatalf("GetOperationResult() error = %v", err)
	}
	if result.Status != status {
		t.Fatalf("operation status = %q, want %q", result.Status, status)
	}
	var recorded protocolasn1.ProfileDownloadTriggerResult
	if err := protocolasn1.Decode(result.Payload, &recorded); err != nil {
		t.Fatalf("Decode(recorded BF54) error = %v", err)
	}
	if !bytes.Equal(recorded.EimTransactionID, fx.eimTx) {
		t.Fatalf("recorded eimTransactionId = %x, want %x", recorded.EimTransactionID, fx.eimTx)
	}
	if recorded.ProfileInstallationSucceeded == nil || *recorded.ProfileInstallationSucceeded != succeeded {
		t.Fatalf("ProfileInstallationSucceeded = %v, want %v", recorded.ProfileInstallationSucceeded, succeeded)
	}
	if recorded.ProfileInstallation == nil || recorded.ProfileInstallation.Data == nil || !bytes.Equal(recorded.ProfileInstallation.Data.TransactionID, fx.smdpTx) {
		t.Fatalf("recorded installation transactionId = %v, want %x", recorded.ProfileInstallation, fx.smdpTx)
	}
}

func assertStillPending(t *testing.T, fx indirectDownload) {
	t.Helper()
	pending, err := fx.store.FetchPendingOperations(fx.ctx, storage.DefaultTenantID, fx.eidKey, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 1 || pending[0].ID != fx.operation.ID {
		t.Fatalf("pending = %#v, want trigger %d", pending, fx.operation.ID)
	}
	if _, err := fx.store.GetOperationResult(fx.ctx, storage.DefaultTenantID, fx.operation.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetOperationResult() error = %v, want %v", err, storage.ErrNotFound)
	}
}

func assertNoEimPackage(t *testing.T, fx indirectDownload) {
	t.Helper()
	response := handleTLV(t, fx.ctx, fx.handler, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: fx.eid}))
	got := encodeResponse(t, response)
	want := []byte{0xbf, 0x4f, 0x03, 0x02, 0x01, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("GetEimPackage = %x, want %x", got, want)
	}
}

func assertNoProfiles(t *testing.T, fx indirectDownload) {
	t.Helper()
	profiles, err := fx.store.ListProfileStates(fx.ctx, storage.DefaultTenantID, fx.eidKey)
	if err != nil {
		t.Fatalf("ListProfileStates() error = %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("profiles = %#v, want none", profiles)
	}
}
