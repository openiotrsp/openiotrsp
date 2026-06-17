package esipa

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/ipadata"
	"github.com/openiotrsp/openiotrsp/pki"
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

func handleUnverified(ctx context.Context, store storage.Store, tenantID storage.TenantID, request Request) (Response, error) {
	return handle(ctx, store, tenantID, request, nil, true, nil)
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

			pollResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
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

			resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
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

			emptyResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
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
	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
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

func TestIpaEuiccDataResponseErrorReturnsEmptyProvideResult(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &recordingStore{Store: memory.New()}
	eid := testEID(0x63)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	operation, err := ipadata.EnqueueRequest(ctx, store, storage.DefaultTenantID, eidKey, ipadata.RequestInput{
		TagList: []byte{0xbf, 0x20},
	})
	if err != nil {
		t.Fatalf("EnqueueRequest() error = %v", err)
	}

	errorResponse := &protocolasn1.IpaEuiccDataResponse{
		Error: &protocolasn1.IpaEuiccDataResponseError{
			Code: protocolasn1.IpaEuiccDataErrorCode(1),
		},
	}
	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLV(t, errorResponse),
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(ProvideEimPackageResult IPA data error) error = %v", err)
	}
	response := decodeProvideResultResponse(t, encodeResponse(t, resultResponse))
	if response.Kind != protocolasn1.ProvideResultResponseEmpty {
		t.Fatalf("provide result kind = %v, want empty response", response.Kind)
	}

	gotOperation, err := store.GetOperation(ctx, storage.DefaultTenantID, operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if gotOperation.Status != storage.OperationFailed {
		t.Fatalf("operation status = %q, want failed", gotOperation.Status)
	}
}

func TestIpaEuiccDataRequestResponsePersistsState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &recordingStore{Store: memory.New()}
	eid := testEID(0x62)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	notificationSeq := int64(11)
	packageResultSeq := int64(12)
	transactionID := []byte{0x01, 0x02, 0x03}
	operation, err := ipadata.EnqueueRequest(ctx, store, storage.DefaultTenantID, eidKey, ipadata.RequestInput{
		TagList:                     []byte{0x5a, 0xbf, 0x20, 0xbf, 0x2d},
		NotificationSeqNumber:       &notificationSeq,
		EuiccPackageResultSeqNumber: &packageResultSeq,
		EimTransactionID:            transactionID,
	})
	if err != nil {
		t.Fatalf("EnqueueRequest() error = %v", err)
	}

	pollResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle(GetEimPackageRequest) error = %v", err)
	}
	poll := decodeGetResponse(t, encodeResponse(t, pollResponse))
	if poll.Kind != protocolasn1.GetEimPackageIpaEuiccDataRequest {
		t.Fatalf("poll kind = %v, want IPA eUICC data request", poll.Kind)
	}
	var polledRequest protocolasn1.IpaEuiccDataRequest
	if err := polledRequest.UnmarshalBERTLV(poll.IpaEuiccDataRequest); err != nil {
		t.Fatalf("UnmarshalBERTLV(polled request) error = %v", err)
	}
	if polledRequest.SearchCriteriaNotification == nil || polledRequest.SearchCriteriaNotification.SeqNumber == nil || *polledRequest.SearchCriteriaNotification.SeqNumber != notificationSeq {
		t.Fatalf("notification search criteria = %#v, want seq %d", polledRequest.SearchCriteriaNotification, notificationSeq)
	}
	if polledRequest.SearchCriteriaEuiccPackageResult == nil || polledRequest.SearchCriteriaEuiccPackageResult.SeqNumber != packageResultSeq {
		t.Fatalf("package-result search criteria = %#v, want seq %d", polledRequest.SearchCriteriaEuiccPackageResult, packageResultSeq)
	}

	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLV(t, sampleIpaEuiccDataResponse(t, eid, transactionID)),
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(ProvideEimPackageResult IPA data) error = %v", err)
	}
	ack := decodeProvideResultResponse(t, encodeResponse(t, resultResponse))
	if ack.Kind != protocolasn1.ProvideResultResponseEmpty {
		t.Fatalf("provide result kind = %v, want empty response", ack.Kind)
	}

	gotOperation, err := store.GetOperation(ctx, storage.DefaultTenantID, operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if gotOperation.Status != storage.OperationDone {
		t.Fatalf("operation status = %q, want done", gotOperation.Status)
	}
	state, err := store.GetEUICCState(ctx, storage.DefaultTenantID, eidKey)
	if err != nil {
		t.Fatalf("GetEUICCState() error = %v", err)
	}
	if state.DefaultSMDPAddress != "smdp.example" || len(state.EUICCInfo1) == 0 || len(state.CertificateIdentifiers) != 2 {
		t.Fatalf("eUICC state = %#v, want default SMDP, info1, and certificate identifiers", state)
	}
	profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eidKey, "89101122334455")
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if !profile.IsEnabled || !profile.IsFallback {
		t.Fatalf("profile state = %#v, want enabled fallback", profile)
	}
}

func TestDefaultHandlerRequiresEUICCPublicKeyResolver(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x5a)
	eidKey := hex.EncodeToString(eid)
	iccid := []byte{0x89, 0x10}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:       eidKey,
		ICCID:     hex.EncodeToString(iccid),
		IsEnabled: false,
	}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}
	request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	request.EuiccPackageSigned.EuiccPackage.PSMOs[0].ICCID = cloneBytes(iccid)
	operation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, request),
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	_, err = Handle(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLV(t, sampleEuiccPackageResultForTag(1, 3, 0)),
			},
		},
	))
	if !errors.Is(err, errMissingEUICCPublicKey) {
		t.Fatalf("Handle(result without resolver) error = %v, want %v", err, errMissingEUICCPublicKey)
	}
	after, err := store.GetOperation(ctx, storage.DefaultTenantID, operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if after.Status != storage.OperationPending {
		t.Fatalf("operation status = %s, want pending", after.Status)
	}
	profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eidKey, hex.EncodeToString(iccid))
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if profile.IsEnabled {
		t.Fatalf("profile state = %#v, want still disabled", profile)
	}
}

func TestDefaultHandlerVerifiesSGP26SignedEUICCPackageResultBeforeApplyingState(t *testing.T) {
	t.Parallel()

	fixture := loadSGP26ResultFixture(t)
	resolver, err := NewStaticEUICCCertificateResolver(
		fixture.ciDER,
		fixture.eumDER,
		fixture.euiccDER,
		pki.WithCurrentTime(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)),
	)
	if err != nil {
		t.Fatalf("NewStaticEUICCCertificateResolver() error = %v", err)
	}

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x5b)
	eidKey := hex.EncodeToString(eid)
	iccid := []byte{0x89, 0x10}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:       eidKey,
		ICCID:     hex.EncodeToString(iccid),
		IsEnabled: false,
	}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}
	request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	request.EuiccPackageSigned.EuiccPackage.PSMOs[0].ICCID = cloneBytes(iccid)
	operation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, request),
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.EUICCPublicKey = resolver

	result := signedEUICCPackageResult(t, fixture.euiccKey, request, operation.SequenceNumber, 3, 0)
	resultResponse, err := handler.handle(ctx, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLVFromDER(t, result),
			},
		},
	))
	if err != nil {
		t.Fatalf("handle(valid signed result) error = %v", err)
	}
	ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(operation.SequenceNumber)}) {
		t.Fatalf("ack = %v, want [%d]", ack.SequenceNumbers, operation.SequenceNumber)
	}
	profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eidKey, hex.EncodeToString(iccid))
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if !profile.IsEnabled {
		t.Fatalf("profile state = %#v, want enabled after verified result", profile)
	}
}

func TestDefaultHandlerRejectsTamperedSGP26SignedEUICCPackageResult(t *testing.T) {
	t.Parallel()

	fixture := loadSGP26ResultFixture(t)
	resolver, err := NewStaticEUICCCertificateResolver(
		fixture.ciDER,
		fixture.eumDER,
		fixture.euiccDER,
		pki.WithCurrentTime(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)),
	)
	if err != nil {
		t.Fatalf("NewStaticEUICCCertificateResolver() error = %v", err)
	}

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x5c)
	eidKey := hex.EncodeToString(eid)
	iccid := []byte{0x89, 0x10}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:       eidKey,
		ICCID:     hex.EncodeToString(iccid),
		IsEnabled: false,
	}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}
	request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	request.EuiccPackageSigned.EuiccPackage.PSMOs[0].ICCID = cloneBytes(iccid)
	operation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, request),
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.EUICCPublicKey = resolver

	result := signedEUICCPackageResult(t, fixture.euiccKey, request, operation.SequenceNumber, 3, 0)
	result[len(result)-1] ^= 0x01
	_, err = handler.handle(ctx, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: mustTLVFromDER(t, result),
			},
		},
	))
	if err == nil {
		t.Fatal("handle(tampered signed result) error = nil, want rejection")
	}
	after, err := store.GetOperation(ctx, storage.DefaultTenantID, operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if after.Status != storage.OperationPending {
		t.Fatalf("operation status = %s, want pending after tampered result", after.Status)
	}
	profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eidKey, hex.EncodeToString(iccid))
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if profile.IsEnabled {
		t.Fatalf("profile state = %#v, want still disabled after tampered result", profile)
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

	firstResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
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

	secondResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
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

	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
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

	thirdResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	if err != nil {
		t.Fatalf("Handle(third poll after result) error = %v", err)
	}
	thirdPoll := decodeGetResponse(t, encodeResponse(t, thirdResponse))
	if thirdPoll.Kind != protocolasn1.GetEimPackageError || thirdPoll.Error == nil || *thirdPoll.Error != getEimPackageErrorNoPackage {
		t.Fatalf("third poll = %#v, want noEimPackageAvailable", thirdPoll)
	}
}

func TestProvideEimPackageResultPersistsAndAcknowledgesNotifications(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x63)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	resultTLV := mustTLV(t, sampleEuiccPackageResult(1))
	notification := samplePendingNotification(t, eid, 17, "enable")
	resultAndNotifications := bertlv.NewChildren(tagSequence,
		resultTLV,
		bertlv.NewChildren(tagNotificationList, notification),
	)
	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: resultAndNotifications,
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(ProvideEimPackageResult with notification) error = %v", err)
	}
	ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1, 17}) {
		t.Fatalf("ack = %v, want [1 17]", ack.SequenceNumbers)
	}

	notifications, err := store.ListNotifications(ctx, storage.DefaultTenantID, eidKey)
	if err != nil {
		t.Fatalf("ListNotifications() error = %v", err)
	}
	if len(notifications) != 1 || notifications[0].SequenceNumber != 17 || notifications[0].Kind != "enable" {
		t.Fatalf("notifications = %#v, want one enable notification with sequence 17", notifications)
	}

	resultResponse, err = handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: resultAndNotifications,
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(redelivered notification) error = %v", err)
	}
	ack = decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1, 17}) {
		t.Fatalf("redelivery ack = %v, want [1 17]", ack.SequenceNumbers)
	}
	notifications, err = store.ListNotifications(ctx, storage.DefaultTenantID, eidKey)
	if err != nil {
		t.Fatalf("ListNotifications(after redelivery) error = %v", err)
	}
	if len(notifications) != 1 {
		t.Fatalf("notifications after redelivery = %#v, want idempotent single record", notifications)
	}
}

func TestHandleNotificationHTTPReturns204AndPersists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x64)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	server := httptest.NewServer(NewHandler(store, storage.DefaultTenantID).HTTPHandler())
	defer server.Close()

	payload := encode(t, &protocolasn1.ESipaMessageFromIpaToEim{
		Raw: bertlv.NewChildren(tagHandleNotify,
			bertlv.NewChildren(tagNotificationList, samplePendingNotification(t, eid, 22, "delete")),
		),
	})
	response, err := server.Client().Post(server.URL+DefaultPath, MediaType, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST HandleNotification error = %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if response.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("HandleNotification response = %s body %x, want empty 204", response.Status, body)
	}
	notifications, err := store.ListNotifications(ctx, storage.DefaultTenantID, eidKey)
	if err != nil {
		t.Fatalf("ListNotifications() error = %v", err)
	}
	if len(notifications) != 1 || notifications[0].SequenceNumber != 22 || notifications[0].Kind != "delete" {
		t.Fatalf("notifications = %#v, want delete sequence 22", notifications)
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

	response, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
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

	response, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
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

	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
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

	emptyResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
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

	_, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
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

func TestProvideEimPackageResult_BF51BareInteger(t *testing.T) {
	t.Parallel()
	runProvideResultVariantTest(t, provideResultVariantCase{
		name: "BF51BareInteger",
		buildResultTLV: func(t *testing.T) *bertlv.TLV {
			t.Helper()
			return bertlv.NewChildren(tagEuiccPackage,
				mustTestIntegerTLV(t, bertlv.Universal.Primitive(2), 127),
			)
		},
		wantStatus: storage.OperationFailed,
	})
}

func TestProvideEimPackageResult_TopLevelInteger(t *testing.T) {
	t.Parallel()
	runProvideResultVariantTest(t, provideResultVariantCase{
		name: "TopLevelInteger",
		buildResultTLV: func(t *testing.T) *bertlv.TLV {
			t.Helper()
			return mustTestIntegerTLV(t, bertlv.Universal.Primitive(2), 127)
		},
		wantStatus: storage.OperationFailed,
	})
}

func TestProvideEimPackageResult_A0Integer(t *testing.T) {
	t.Parallel()
	runProvideResultVariantTest(t, provideResultVariantCase{
		name: "A0Integer",
		buildResultTLV: func(t *testing.T) *bertlv.TLV {
			t.Helper()
			return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
				mustTestIntegerTLV(t, bertlv.Universal.Primitive(2), 2),
			)
		},
		wantStatus: storage.OperationFailed,
	})
}

func TestEuiccPackageResultSigned_IntegerResult(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &recordingStore{Store: memory.New()}
	eid := testEID(0x71)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, request),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	resultTLV := signedEuiccPackageResultIntegerList(t, request, 1, 3, 0)
	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: resultTLV,
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(ProvideEimPackageResult signed integer result) error = %v", err)
	}
	ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1}) {
		t.Fatalf("ack = %v, want [1]", ack.SequenceNumbers)
	}
	results := store.recordedResults()
	if len(results) != 1 || results[0].Status != storage.OperationDone {
		t.Fatalf("recorded results = %#v, want one done result", results)
	}
}

type provideResultVariantCase struct {
	name           string
	buildResultTLV func(t *testing.T) *bertlv.TLV
	wantStatus     storage.OperationStatus
}

func runProvideResultVariantTest(t *testing.T, tc provideResultVariantCase) {
	t.Helper()

	ctx := context.Background()
	store := &recordingStore{Store: memory.New()}
	eid := testEID(0x70)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	resultResponse, err := handleUnverified(ctx, store, storage.DefaultTenantID, envelopeRequest(t,
		&protocolasn1.ProvideEimPackageResult{
			EID: eid,
			EimPackageResult: protocolasn1.EimPackageResult{
				Raw: tc.buildResultTLV(t),
			},
		},
	))
	if err != nil {
		t.Fatalf("Handle(%s) error = %v", tc.name, err)
	}
	ack := decodeProvideResultAck(t, encodeResponse(t, resultResponse))
	if !reflect.DeepEqual(ack.SequenceNumbers, []protocolasn1.SequenceNumber{1}) {
		t.Fatalf("ack = %v, want [1]", ack.SequenceNumbers)
	}
	results := store.recordedResults()
	if len(results) != 1 || results[0].Status != tc.wantStatus {
		t.Fatalf("recorded results = %#v, want one %s result", results, tc.wantStatus)
	}
}

func signedEuiccPackageResultIntegerList(
	t *testing.T,
	request *protocolasn1.EuiccPackageRequest,
	sequenceNumber int64,
	resultTag uint64,
	resultCode int64,
) *bertlv.TLV {
	t.Helper()
	result, err := protocolasn1.IntegerEuiccResult(resultTag, resultCode)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	data := bertlv.NewChildren(bertlv.Universal.Constructed(16),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte(request.EuiccPackageSigned.EimID)),
		mustTestIntegerTLV(t, bertlv.ContextSpecific.Primitive(1), request.EuiccPackageSigned.CounterValue),
		mustTestIntegerTLV(t, bertlv.ContextSpecific.Primitive(3), sequenceNumber),
		result.Raw,
	)
	signature := []byte{0x30, 0x03, 0x02, 0x01, 0x02}
	return bertlv.NewChildren(tagEuiccPackage,
		bertlv.NewChildren(bertlv.Universal.Constructed(16),
			data,
			bertlv.NewValue(bertlv.Application.Primitive(55), signature),
		),
	)
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

	_, _, err := recordEimPackageResult(ctx, store, storage.DefaultTenantID, eidKey, bertlv.NewChildren(bertlv.ContextSpecific.Constructed(99)), nil, true)
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

	handler := NewHandler(store, storage.DefaultTenantID)
	handler.AllowUnverifiedEUICCPackageResults = true
	client := transport(t, handler)
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

func decodeProvideResultResponse(t *testing.T, payload []byte) protocolasn1.ProvideEimPackageResultResponse {
	t.Helper()
	var message protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(payload, &message); err != nil {
		t.Fatalf("Decode(eIM envelope) error = %v", err)
	}
	var response protocolasn1.ProvideEimPackageResultResponse
	if err := response.UnmarshalBERTLV(message.Raw); err != nil {
		t.Fatalf("UnmarshalBERTLV(ProvideEimPackageResultResponse) error = %v", err)
	}
	return response
}

func decodeProvideResultAck(t *testing.T, payload []byte) protocolasn1.EimAcknowledgements {
	t.Helper()
	response := decodeProvideResultResponse(t, payload)
	if response.Kind != protocolasn1.ProvideResultResponseAcknowledgements {
		t.Fatalf("provide result kind = %v, want acknowledgements", response.Kind)
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

func samplePendingNotification(t *testing.T, eid []byte, sequenceNumber int64, kind string) *bertlv.TLV {
	t.Helper()
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1),
		bertlv.NewValue(tagEID, cloneBytes(eid)),
		bertlv.NewChildren(tagNotificationMeta,
			mustTestIntegerTLV(t, bertlv.ContextSpecific.Primitive(0), sequenceNumber),
			mustTestBitStringTLV(t, bertlv.ContextSpecific.Primitive(1), notificationEventBits(kind)),
			bertlv.NewValue(bertlv.Universal.Primitive(12), []byte("notification.openiotrsp.local")),
		),
		bertlv.NewValue(bertlv.Application.Primitive(55), []byte{0x30, 0x00}),
	)
}

func notificationEventBits(kind string) []bool {
	bits := make([]bool, 4)
	switch kind {
	case "install":
		bits[0] = true
	case "enable":
		bits[1] = true
	case "disable":
		bits[2] = true
	case "delete":
		bits[3] = true
	}
	return bits
}

func mustTestIntegerTLV(t *testing.T, tag bertlv.Tag, value int64) *bertlv.TLV {
	t.Helper()
	tlv, err := bertlv.MarshalValue(tag, primitive.MarshalInt(value))
	if err != nil {
		t.Fatalf("MarshalValue(INTEGER) error = %v", err)
	}
	return tlv
}

func mustTestBitStringTLV(t *testing.T, tag bertlv.Tag, bits []bool) *bertlv.TLV {
	t.Helper()
	tlv, err := bertlv.MarshalValue(tag, primitive.MarshalBitString(bits))
	if err != nil {
		t.Fatalf("MarshalValue(BIT STRING) error = %v", err)
	}
	return tlv
}

func sampleIpaEuiccDataResponse(t *testing.T, eid []byte, transactionID []byte) *protocolasn1.IpaEuiccDataResponse {
	t.Helper()
	state := protocolasn1.ProfileStateEnabled
	profiles, err := (&protocolasn1.ProfileInfoListResponse{
		Profiles: []protocolasn1.ProfileInfo{{
			ICCID:             []byte{0x89, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55},
			ProfileState:      &state,
			FallbackAttribute: true,
		}},
	}).MarshalBERTLV()
	if err != nil {
		t.Fatalf("ProfileInfoListResponse MarshalBERTLV() error = %v", err)
	}
	return &protocolasn1.IpaEuiccDataResponse{
		Data: &protocolasn1.IpaEuiccData{
			RawObjects: []*bertlv.TLV{
				bertlv.NewValue(tagEID, eid),
				bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte("smdp.example")),
				bertlv.NewChildren(bertlv.ContextSpecific.Constructed(32),
					bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x03, 0x02, 0x01}),
					bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
						bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xaa, 0x01}),
					),
					bertlv.NewChildren(bertlv.ContextSpecific.Constructed(10),
						bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xbb, 0x02}),
					),
				),
				profiles,
				bertlv.NewValue(bertlv.ContextSpecific.Primitive(7), transactionID),
			},
		},
	}
}

type sgp26ResultFixture struct {
	ciDER    []byte
	eumDER   []byte
	euiccDER []byte
	euiccKey *ecdsa.PrivateKey
}

func loadSGP26ResultFixture(t *testing.T) sgp26ResultFixture {
	t.Helper()
	const fixturePath = "../spec/SGP.26_v3.0.2-17-July-2025.zip"
	entries := map[string]string{
		"ci":      "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/CI/CERT_CI_SIG_NIST.der",
		"euicc":   "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/CERT_EUICC_SIG_NIST.der",
		"eum":     "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EUM/CERT_EUM_SIG_NIST.der",
		"euiccSK": "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/SK_EUICC_SIG_NIST.pem",
	}
	if _, err := os.Stat(fixturePath); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("SGP.26 ZIP not present at %s", fixturePath)
		}
		t.Fatalf("stat SGP.26 ZIP: %v", err)
	}
	reader, err := zip.OpenReader(fixturePath)
	if err != nil {
		t.Fatalf("open SGP.26 ZIP: %v", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Fatalf("close SGP.26 ZIP: %v", err)
		}
	}()
	files := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		files[file.Name] = file
	}
	readEntry := func(name string) []byte {
		t.Helper()
		file := files[entries[name]]
		if file == nil {
			t.Fatalf("SGP.26 ZIP missing %s", entries[name])
		}
		opened, err := file.Open()
		if err != nil {
			t.Fatalf("open %s: %v", file.Name, err)
		}
		defer func() {
			if err := opened.Close(); err != nil {
				t.Fatalf("close %s: %v", file.Name, err)
			}
		}()
		data, err := io.ReadAll(opened)
		if err != nil {
			t.Fatalf("read %s: %v", file.Name, err)
		}
		return data
	}
	return sgp26ResultFixture{
		ciDER:    readEntry("ci"),
		eumDER:   readEntry("eum"),
		euiccDER: readEntry("euicc"),
		euiccKey: parseECDSAPrivateKey(t, readEntry("euiccSK")),
	}
}

func parseECDSAPrivateKey(t *testing.T, pemBytes []byte) *ecdsa.PrivateKey {
	t.Helper()
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		pemBytes = rest
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if ok {
			return ecdsaKey
		}
	}
	t.Fatal("parse SGP.26 eUICC private key")
	return nil
}

func signedEUICCPackageResult(t *testing.T, key *ecdsa.PrivateKey, request *protocolasn1.EuiccPackageRequest, sequenceNumber int64, resultTag uint64, resultCode int64) []byte {
	t.Helper()
	result, err := protocolasn1.IntegerEuiccResult(resultTag, resultCode)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	data := protocolasn1.EuiccPackageResultDataSigned{
		EimID:            request.EuiccPackageSigned.EimID,
		CounterValue:     request.EuiccPackageSigned.CounterValue,
		EimTransactionID: cloneBytes(request.EuiccPackageSigned.EimTransactionID),
		SeqNumber:        sequenceNumber,
		Results:          []protocolasn1.EuiccResultData{result},
	}
	dataDER := encode(t, &data)
	digest := sha256.Sum256(dataDER)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}
	return encode(t, &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultOK,
		Signed: &protocolasn1.EuiccPackageResultSigned{
			Data:         data,
			EuiccSignEPR: signature,
		},
	})
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

func mustTLVFromDER(t *testing.T, der []byte) *protocolasn1.TLV {
	t.Helper()
	tlv := new(protocolasn1.TLV)
	if err := tlv.UnmarshalBinary(der); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
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
