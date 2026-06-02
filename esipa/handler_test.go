package esipa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
	piondtls "github.com/pion/dtls/v3"
	coapdtls "github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/net/blockwise"
	"github.com/plgd-dev/go-coap/v3/options"
)

type transportClient func(t *testing.T, payload []byte) []byte

type scenarioObservation struct {
	PollKind       protocolasn1.GetEimPackageResponseKind
	PackageDER     []byte
	Acknowledged   []protocolasn1.SequenceNumber
	EmptyPollError protocolasn1.EimPackageResultErrorCode
	RecordedStatus storage.OperationStatus
}

func TestSGP33ESipaTransportParity(t *testing.T) {
	// SGP.33-1 v1.2 defines the eUICC-side ESep package/result exchanges and
	// TC_IPAe_HTTPS_Nominal covers HTTPS session establishment. ESipa polling is
	// the SGP.32 transport path that carries those package/result payloads between
	// IPA and eIM, so this test asserts HTTPS and CoAP/DTLS decode identically.
	httpObservation := runPollAndResultScenario(t, newHTTPTransportClient)
	coapObservation := runPollAndResultScenario(t, newCoAPDTLSTransportClient)

	if !reflect.DeepEqual(httpObservation, coapObservation) {
		t.Fatalf("HTTP and CoAP/DTLS observations differ\nHTTP: %#v\nCoAP: %#v", httpObservation, coapObservation)
	}
}

func TestSGP33ESepPackageResultsThroughESipa(t *testing.T) {
	t.Parallel()

	// Extracted from SGP.33-1 v1.2:
	// - 4.2.31 Enable: nominal ENABLE_RES_OK_1 and error enableResult values.
	// - 4.2.32 Disable: nominal DISABLE_RES_OK_1 and error disableResult values.
	// - 4.2.33 Delete: nominal DELETE_RES_OK_1 and error deleteResult values.
	// - Annex D.1.2 pins the symbolic result bodies to result tags/codes.
	cases := []struct {
		name       string
		operation  protocolasn1.PsmoOperation
		resultTag  uint64
		resultCode int64
		wantStatus storage.OperationStatus
	}{
		{name: "4.2.31 Enable nominal ENABLE_RES_OK_1", operation: protocolasn1.PsmoEnable, resultTag: 3, resultCode: 0, wantStatus: storage.OperationDone},
		{name: "4.2.31 Enable target profile not found", operation: protocolasn1.PsmoEnable, resultTag: 3, resultCode: 1, wantStatus: storage.OperationFailed},
		{name: "4.2.31 Enable profile not disabled", operation: protocolasn1.PsmoEnable, resultTag: 3, resultCode: 2, wantStatus: storage.OperationFailed},
		{name: "4.2.31 Enable rollback unavailable", operation: protocolasn1.PsmoEnable, resultTag: 3, resultCode: 20, wantStatus: storage.OperationFailed},
		{name: "4.2.31 Enable undefined error", operation: protocolasn1.PsmoEnable, resultTag: 3, resultCode: 127, wantStatus: storage.OperationFailed},
		{name: "4.2.32 Disable nominal DISABLE_RES_OK_1", operation: protocolasn1.PsmoDisable, resultTag: 4, resultCode: 0, wantStatus: storage.OperationDone},
		{name: "4.2.32 Disable target profile not found", operation: protocolasn1.PsmoDisable, resultTag: 4, resultCode: 1, wantStatus: storage.OperationFailed},
		{name: "4.2.32 Disable profile not enabled", operation: protocolasn1.PsmoDisable, resultTag: 4, resultCode: 2, wantStatus: storage.OperationFailed},
		{name: "4.2.33 Delete nominal DELETE_RES_OK_1", operation: protocolasn1.PsmoDelete, resultTag: 5, resultCode: 0, wantStatus: storage.OperationDone},
		{name: "4.2.33 Delete target profile not found", operation: protocolasn1.PsmoDelete, resultTag: 5, resultCode: 1, wantStatus: storage.OperationFailed},
		{name: "4.2.33 Delete profile not disabled", operation: protocolasn1.PsmoDelete, resultTag: 5, resultCode: 2, wantStatus: storage.OperationFailed},
	}

	for index, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store := &recordingStore{Store: memory.New()}
			eid := testEID(byte(0x50 + index))
			eidKey := hex.EncodeToString(eid)
			if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
				t.Fatalf("RegisterDevice() error = %v", err)
			}

			request := samplePSMOEuiccPackageRequest(eid, tc.operation, 3)
			if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
				EID:     eidKey,
				Kind:    storage.OperationEuiccPackage,
				Payload: encode(t, request),
			}); err != nil {
				t.Fatalf("EnqueueOperation() error = %v", err)
			}

			pollResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
			if err != nil {
				t.Fatalf("Handle(GetEimPackageRequest) error = %v", err)
			}
			poll := decodeGetResponse(t, encodeResponse(t, pollResponse))
			if poll.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
				t.Fatalf("poll kind = %v, want eUICC package request", poll.Kind)
			}
			if got := poll.EuiccPackageRequest.EuiccPackageSigned.EuiccPackage.PSMOs[0].Operation; got != tc.operation {
				t.Fatalf("polled PSMO operation = %v, want %v", got, tc.operation)
			}

			resultResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
				&protocolasn1.ProvideEimPackageResult{
					EID: eid,
					EimPackageResult: protocolasn1.EimPackageResult{
						Raw: mustTLV(t, sampleEuiccPackageResultForTag(1, tc.resultTag, tc.resultCode)),
					},
				},
			))
			if err != nil {
				t.Fatalf("Handle(ProvideEimPackageResult) error = %v", err)
			}
			ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
			if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1}) {
				t.Fatalf("ack = %v, want [1]", ack.SequenceNumbers)
			}
			results := store.recordedResults()
			if len(results) != 1 || results[0].Status != tc.wantStatus {
				t.Fatalf("recorded results = %#v, want one %s result", results, tc.wantStatus)
			}

			emptyResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
			if err != nil {
				t.Fatalf("Handle(second GetEimPackageRequest) error = %v", err)
			}
			empty := decodeGetResponse(t, encodeResponse(t, emptyResponse))
			if empty.Kind != protocolasn1.GetEimPackageError || empty.Error == nil || *empty.Error != getEimPackageErrorNoPackage {
				t.Fatalf("second poll = %#v, want noEimPackageAvailable", empty)
			}
		})
	}
}

func TestEUICCPackageResultWithoutSequenceMatchesByTransactionAndCounter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &recordingStore{Store: memory.New()}
	eid := testEID(0x59)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	transactionID := []byte{0x01, 0x02, 0x03, 0x04}
	firstRequest := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	firstRequest.EuiccPackageSigned.CounterValue = 1
	firstRequest.EuiccPackageSigned.EimTransactionID = cloneBytes(transactionID)
	firstOperation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, firstRequest),
	})
	if err != nil {
		t.Fatalf("EnqueueOperation(first) error = %v", err)
	}

	secondRequest := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	secondRequest.EuiccPackageSigned.CounterValue = 2
	secondRequest.EuiccPackageSigned.EimTransactionID = cloneBytes(transactionID)
	secondOperation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, secondRequest),
	})
	if err != nil {
		t.Fatalf("EnqueueOperation(second) error = %v", err)
	}

	result := sampleEuiccPackageResultForTag(0, 3, 0)
	result.Signed.Data.CounterValue = secondRequest.EuiccPackageSigned.CounterValue
	result.Signed.Data.EimTransactionID = cloneBytes(transactionID)
	resultResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLV(t, result),
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(ProvideEimPackageResult) error = %v", err)
	}
	ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(secondOperation.SequenceNumber)}) {
		t.Fatalf("ack = %v, want [%d]", ack.SequenceNumbers, secondOperation.SequenceNumber)
	}

	results := store.recordedResults()
	if len(results) != 1 {
		t.Fatalf("recorded results = %#v, want one result", results)
	}
	if results[0].OperationID != secondOperation.ID || results[0].SequenceNumber != secondOperation.SequenceNumber {
		t.Fatalf("recorded result = %#v, want operation %d sequence %d", results[0], secondOperation.ID, secondOperation.SequenceNumber)
	}

	firstAfter, err := store.GetOperation(ctx, storage.DefaultTenantID, firstOperation.ID)
	if err != nil {
		t.Fatalf("GetOperation(first) error = %v", err)
	}
	if firstAfter.Status != storage.OperationPending {
		t.Fatalf("first operation status = %s, want pending", firstAfter.Status)
	}
	secondAfter, err := store.GetOperation(ctx, storage.DefaultTenantID, secondOperation.ID)
	if err != nil {
		t.Fatalf("GetOperation(second) error = %v", err)
	}
	if secondAfter.Status != storage.OperationDone {
		t.Fatalf("second operation status = %s, want done", secondAfter.Status)
	}
}

func TestUnacknowledgedPackageRedeliversUntilResultRecorded(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x61)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	request := sampleEuiccPackageRequest(eid, 3)
	requestDER := encode(t, request)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: requestDER,
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	firstResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle(first poll) error = %v", err)
	}
	firstPoll := decodeGetResponse(t, encodeResponse(t, firstResponse))
	if firstPoll.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("first poll kind = %v, want eUICC package", firstPoll.Kind)
	}
	if !bytes.Equal(encode(t, firstPoll.EuiccPackageRequest), requestDER) {
		t.Fatalf("first poll package mismatch")
	}

	secondResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle(second poll without result) error = %v", err)
	}
	secondPoll := decodeGetResponse(t, encodeResponse(t, secondResponse))
	if secondPoll.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("second poll kind = %v, want redelivered eUICC package", secondPoll.Kind)
	}
	if !bytes.Equal(encode(t, secondPoll.EuiccPackageRequest), requestDER) {
		t.Fatalf("redelivered package changed")
	}

	resultResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLV(t, sampleEuiccPackageResult(1)),
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(result upload) error = %v", err)
	}
	ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1}) {
		t.Fatalf("ack = %v, want [1]", ack.SequenceNumbers)
	}

	thirdResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle(third poll after result) error = %v", err)
	}
	thirdPoll := decodeGetResponse(t, encodeResponse(t, thirdResponse))
	if thirdPoll.Kind != protocolasn1.GetEimPackageError || thirdPoll.Error == nil || *thirdPoll.Error != getEimPackageErrorNoPackage {
		t.Fatalf("third poll = %#v, want noEimPackageAvailable", thirdPoll)
	}
}

func TestEmptyPollReturnsNoPackageAvailable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x22)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: hex.EncodeToString(eid)}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	response, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	decoded := decodeGetResponse(t, encodeResponse(t, response))
	if decoded.Kind != protocolasn1.GetEimPackageError || decoded.Error == nil || *decoded.Error != getEimPackageErrorNoPackage {
		t.Fatalf("empty poll response = %#v, want noEimPackageAvailable(1)", decoded)
	}
}

func TestProfileDownloadTriggerPoll(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &recordingStore{Store: memory.New()}
	eid := testEID(0x33)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := []byte{0x01, 0x02}
	trigger, err := profiledownload.NewActivationCodeTrigger("1$example.com$ACT", transactionID)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}

	response, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	decoded := decodeGetResponse(t, encodeResponse(t, response))
	if decoded.Kind != protocolasn1.GetEimPackageProfileDownloadTriggerRequest {
		t.Fatalf("response kind = %v, want profile download trigger", decoded.Kind)
	}
	if decoded.ProfileDownloadTriggerRequest == nil || decoded.ProfileDownloadTriggerRequest.ProfileDownloadData.ActivationCode != "1$example.com$ACT" {
		t.Fatalf("trigger response = %#v", decoded.ProfileDownloadTriggerRequest)
	}

	resultResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLV(t, &protocolasn1.ProfileDownloadTriggerResult{
					EimTransactionID: transactionID,
					ProfileInstallationRaw: profileInstallationResultTLV(
						bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0)),
					),
				}),
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(profile download result) error = %v", err)
	}
	ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1}) {
		t.Fatalf("ack = %v, want [1]", ack.SequenceNumbers)
	}
	results := store.recordedResults()
	if len(results) != 1 || results[0].Status != storage.OperationDone {
		t.Fatalf("recorded results = %#v, want one done result", results)
	}

	emptyResponse, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle(second poll after profile result) error = %v", err)
	}
	empty := decodeGetResponse(t, encodeResponse(t, emptyResponse))
	if empty.Kind != protocolasn1.GetEimPackageError || empty.Error == nil || *empty.Error != getEimPackageErrorNoPackage {
		t.Fatalf("second poll = %#v, want noEimPackageAvailable", empty)
	}
}

func TestProfileDownloadTriggerFailedInstallRecordsFailed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &recordingStore{Store: memory.New()}
	eid := testEID(0x34)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := []byte{0x03, 0x04}
	trigger := profiledownload.NewDefaultSMDPTrigger(transactionID)
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}

	_, err := Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLV(t, &protocolasn1.ProfileDownloadTriggerResult{
					EimTransactionID: transactionID,
					ProfileInstallationRaw: profileInstallationResultTLV(
						bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1)),
					),
				}),
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(profile download failed install) error = %v", err)
	}
	results := store.recordedResults()
	if len(results) != 1 || results[0].Status != storage.OperationFailed {
		t.Fatalf("recorded results = %#v, want one failed result", results)
	}
	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %#v, want trigger removed after failed result", pending)
	}
}

func TestUnknownEimPackageResultFailsClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x35)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	_, err := recordEimPackageResult(ctx, store, storage.DefaultTenantID, eidKey, bertlv.NewChildren(bertlv.ContextSpecific.Constructed(99)))
	if err == nil {
		t.Fatal("recordEimPackageResult() succeeded for unknown result tag, want rejection")
	}
}

func TestCoAPDTLSBlockwiseLargePackage(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x44)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	largeRequest := sampleEuiccPackageRequest(eid, 4096)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, largeRequest),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	client := newCoAPDTLSTransportClient(t, NewHandler(store, storage.DefaultTenantID))
	getResponse := decodeGetResponse(t, client(t, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid})))
	if getResponse.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("response kind = %v, want eUICC package", getResponse.Kind)
	}
	gotDER := encode(t, getResponse.EuiccPackageRequest)
	if !bytes.Equal(gotDER, encode(t, largeRequest)) {
		t.Fatalf("large blockwise package changed\n got %d bytes\nwant %d bytes", len(gotDER), len(encode(t, largeRequest)))
	}
}

func runPollAndResultScenario(t *testing.T, transport func(*testing.T, *Handler) transportClient) scenarioObservation {
	t.Helper()

	ctx := context.Background()
	backing := memory.New()
	store := &recordingStore{Store: backing}
	eid := testEID(0x11)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	queuedRequest := sampleEuiccPackageRequest(eid, 3)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, queuedRequest),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	client := transport(t, NewHandler(store, storage.DefaultTenantID))
	pollPayload := client(t, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid, NotifyStateChange: true}))
	poll := decodeGetResponse(t, pollPayload)
	if poll.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("poll kind = %v, want eUICC package", poll.Kind)
	}

	resultPayload := client(t, encodeProvideResult(t, eid, sampleEuiccPackageResult(1)))
	ack := decodeProvideResultAck(t, resultPayload)
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1}) {
		t.Fatalf("ack = %v, want [1]", ack.SequenceNumbers)
	}

	emptyPayload := client(t, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	empty := decodeGetResponse(t, emptyPayload)
	if empty.Kind != protocolasn1.GetEimPackageError || empty.Error == nil {
		t.Fatalf("empty poll = %#v, want error response", empty)
	}
	results := store.recordedResults()
	if len(results) != 1 {
		t.Fatalf("recorded %d results, want 1", len(results))
	}

	return scenarioObservation{
		PollKind:       poll.Kind,
		PackageDER:     encode(t, poll.EuiccPackageRequest),
		Acknowledged:   ack.SequenceNumbers,
		EmptyPollError: *empty.Error,
		RecordedStatus: results[0].Status,
	}
}

func newHTTPTransportClient(t *testing.T, h *Handler) transportClient {
	t.Helper()
	server := httptest.NewTLSServer(h.HTTPHandler())
	t.Cleanup(server.Close)
	client := server.Client()

	return func(t *testing.T, payload []byte) []byte {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, server.URL+h.path(), bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		request.Header.Set("Content-Type", MediaType)
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("HTTP POST error = %v", err)
		}
		defer func() {
			_ = response.Body.Close()
		}()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("HTTP status = %s", response.Status)
		}
		if !response.Close {
			t.Fatalf("HTTP response Close = false, want connection close for poll request")
		}
		out, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read HTTP response: %v", err)
		}
		return out
	}
}

func newCoAPDTLSTransportClient(t *testing.T, h *Handler) transportClient {
	t.Helper()

	certificate := testCertificate(t)
	listener, err := coapnet.NewDTLSListener("udp", "127.0.0.1:0", coapnet.NewDTLSServerOptions(
		piondtls.WithCertificates(certificate),
	))
	if err != nil {
		t.Fatalf("NewDTLSListener() error = %v", err)
	}

	server := coapdtls.NewServer(
		options.WithMux(h.CoAPHandler()),
		options.WithMaxMessageSize(uint32(h.maxMessageSize())),
		options.WithBlockwise(false, blockwise.SZX1024, time.Second),
	)
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		if err := server.Serve(listener); err != nil {
			t.Errorf("CoAP/DTLS Serve() error = %v", err)
		}
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		serverWG.Wait()
	})

	client, err := coapdtls.Dial(listener.Addr().String(), coapdtls.NewDTLSClientOptions(
		piondtls.WithInsecureSkipVerify(true),
	),
		options.WithBlockwise(true, blockwise.SZX64, time.Second),
		options.WithMaxMessageSize(uint32(h.maxMessageSize())),
	)
	if err != nil {
		t.Fatalf("CoAP/DTLS Dial() error = %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		<-client.Done()
	})

	return func(t *testing.T, payload []byte) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		response, err := client.Post(ctx, h.path(), message.AppOctets, bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("CoAP POST error = %v", err)
		}
		if response.Code() != codes.Content {
			t.Fatalf("CoAP code = %v, want Content", response.Code())
		}
		out, err := io.ReadAll(response.Body())
		if err != nil {
			t.Fatalf("read CoAP response: %v", err)
		}
		return out
	}
}

type recordingStore struct {
	storage.Store
	mu      sync.Mutex
	results []storage.EUICCPackageResult
}

func (s *recordingStore) RecordEUICCPackageResult(ctx context.Context, tenantID storage.TenantID, result storage.EUICCPackageResult) error {
	if err := s.Store.RecordEUICCPackageResult(ctx, tenantID, result); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result.Payload = cloneBytes(result.Payload)
	s.results = append(s.results, result)
	return nil
}

func (s *recordingStore) recordedResults() []storage.EUICCPackageResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storage.EUICCPackageResult, len(s.results))
	copy(out, s.results)
	return out
}

func envelopeRequest(t *testing.T, value protocolasn1.Marshaler) Request {
	t.Helper()
	var message protocolasn1.ESipaMessageFromIpaToEim
	if err := protocolasn1.Decode(encodeEnvelope(t, value), &message); err != nil {
		t.Fatalf("Decode(envelope) error = %v", err)
	}
	return Request{Message: message}
}

func encodeEnvelope(t *testing.T, value protocolasn1.Marshaler) []byte {
	t.Helper()
	tlv, err := value.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	return encode(t, &protocolasn1.ESipaMessageFromIpaToEim{Raw: tlv})
}

func encodeResponse(t *testing.T, response Response) []byte {
	t.Helper()
	payload, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	return payload
}

func encodeProvideResult(t *testing.T, eid []byte, result *protocolasn1.EuiccPackageResult) []byte {
	t.Helper()
	tlv, err := result.MarshalBERTLV()
	if err != nil {
		t.Fatalf("result MarshalBERTLV() error = %v", err)
	}
	return encodeEnvelope(t, &protocolasn1.ProvideEimPackageResult{
		EID:              eid,
		EimPackageResult: protocolasn1.EimPackageResult{Raw: tlv},
	})
}

func decodeGetResponse(t *testing.T, payload []byte) protocolasn1.GetEimPackageResponse {
	t.Helper()
	var message protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(payload, &message); err != nil {
		t.Fatalf("Decode(eIM envelope) error = %v", err)
	}
	var response protocolasn1.GetEimPackageResponse
	if err := response.UnmarshalBERTLV(message.Raw); err != nil {
		t.Fatalf("UnmarshalBERTLV(GetEimPackageResponse) error = %v", err)
	}
	return response
}

func decodeProvideResultAck(t *testing.T, payload []byte) protocolasn1.EimAcknowledgements {
	t.Helper()
	var message protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(payload, &message); err != nil {
		t.Fatalf("Decode(eIM envelope) error = %v", err)
	}
	var response protocolasn1.ProvideEimPackageResultResponse
	if err := response.UnmarshalBERTLV(message.Raw); err != nil {
		t.Fatalf("UnmarshalBERTLV(ProvideEimPackageResultResponse) error = %v", err)
	}
	var ack protocolasn1.EimAcknowledgements
	if err := ack.UnmarshalBERTLV(response.Raw); err != nil {
		t.Fatalf("UnmarshalBERTLV(EimAcknowledgements) error = %v", err)
	}
	return ack
}

func sampleEuiccPackageRequest(eid []byte, signatureLen int) *protocolasn1.EuiccPackageRequest {
	return samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, signatureLen)
}

func samplePSMOEuiccPackageRequest(eid []byte, operation protocolasn1.PsmoOperation, signatureLen int) *protocolasn1.EuiccPackageRequest {
	return &protocolasn1.EuiccPackageRequest{
		EuiccPackageSigned: protocolasn1.EuiccPackageSigned{
			EimID:        "testeim1",
			EID:          cloneBytes(eid),
			CounterValue: 1,
			EuiccPackage: protocolasn1.EuiccPackage{
				Kind: protocolasn1.EuiccPackagePSMO,
				PSMOs: []protocolasn1.Psmo{{
					Operation: operation,
					ICCID:     []byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1},
				}},
			},
		},
		EimSignature: bytes.Repeat([]byte{0xa5}, signatureLen),
	}
}

func sampleEuiccPackageResult(sequence int64) *protocolasn1.EuiccPackageResult {
	return sampleEuiccPackageResultForTag(sequence, 3, 0)
}

func sampleEuiccPackageResultForTag(sequence int64, resultTag uint64, resultCode int64) *protocolasn1.EuiccPackageResult {
	result, err := protocolasn1.IntegerEuiccResult(resultTag, resultCode)
	if err != nil {
		panic(err)
	}
	return &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultOK,
		Signed: &protocolasn1.EuiccPackageResultSigned{
			Data: protocolasn1.EuiccPackageResultDataSigned{
				EimID:        "testeim1",
				CounterValue: 1,
				SeqNumber:    sequence,
				Results:      []protocolasn1.EuiccResultData{result},
			},
			EuiccSignEPR: []byte{0x30, 0x03, 0x02, 0x01, 0x02},
		},
	}
}

func profileInstallationResultTLV(finalResultChild *bertlv.TLV) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(55),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(39),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2), finalResultChild),
		),
	)
}

func mustTLV(t *testing.T, value protocolasn1.Marshaler) *protocolasn1.TLV {
	t.Helper()
	tlv, err := value.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	return tlv
}

func encode(t *testing.T, value protocolasn1.Marshaler) []byte {
	t.Helper()
	payload, err := protocolasn1.Encode(value)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	return payload
}

func testEID(last byte) []byte {
	eid := make([]byte, 16)
	eid[15] = last
	return eid
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	return certificate
}
