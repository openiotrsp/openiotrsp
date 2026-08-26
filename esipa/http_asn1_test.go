package esipa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

// plugfestEID is the Kigen eUICC used for the SGP.32 section 6.1.1 probe that
// exposed the non-conformant ASN.1 binding.
const plugfestEID = "89044045930000000000002153893210"

// TestASN1BindingSection611 pins the SGP.32 v1.3 section 6.1.1 ASN.1 binding:
// the generic '/gsma/rsp2/asn1' path, the mandated X-Admin-Protocol and
// Content-Type response headers, and a body holding exactly one
// EsipaMessageFromEimToIpa. An IPAe discards responses that miss any of these.
func TestASN1BindingSection611(t *testing.T) {
	t.Parallel()

	eid, err := hex.DecodeString(plugfestEID)
	if err != nil {
		t.Fatalf("DecodeString(plugfestEID) error = %v", err)
	}

	// Known answer from the Plugfest probe: BF4F 12 5A 10 <EID> is the
	// GetEimPackageRequest an IPAe puts on the wire for this eUICC.
	wantRequest := append([]byte{0xbf, 0x4f, 0x12, 0x5a, 0x10}, eid...)
	if got := encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid}); !bytes.Equal(got, wantRequest) {
		t.Fatalf("getEimPackageRequest = %x, want %x", got, wantRequest)
	}

	tests := []struct {
		name          string
		path          string
		adminProtocol string
		wantProtocol  string
	}{
		{
			name:          "generic ASN.1 path echoes the negotiated version",
			path:          GSMAPathASN1,
			adminProtocol: "gsma/rsp/v2.1.0",
			wantProtocol:  "gsma/rsp/v2.1.0",
		},
		{
			name:         "generic ASN.1 path falls back to the ESipa default",
			path:         GSMAPathASN1,
			wantProtocol: DefaultAdminProtocol,
		},
		{
			name:         "legacy path stays mounted for pinned consumers",
			path:         DefaultPath,
			wantProtocol: DefaultAdminProtocol,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := memory.New()
			if err := store.RegisterDevice(context.Background(), storage.DefaultTenantID, storage.Device{EID: plugfestEID}); err != nil {
				t.Fatalf("RegisterDevice() error = %v", err)
			}
			server := httptest.NewServer(NewHandler(store, storage.DefaultTenantID).HTTPHandler())
			t.Cleanup(server.Close)

			request, err := http.NewRequest(http.MethodPost, server.URL+test.path, bytes.NewReader(wantRequest))
			if err != nil {
				t.Fatalf("NewRequest() error = %v", err)
			}
			request.Header.Set("Content-Type", ASN1MediaType)
			request.Header.Set("User-Agent", "gsma-rsp-ipae")
			if test.adminProtocol != "" {
				request.Header.Set(adminProtocolHeader, test.adminProtocol)
			}
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatalf("POST %s error = %v", test.path, err)
			}
			defer func() { _ = response.Body.Close() }()

			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %s, want 200 OK", response.Status)
			}
			if got := response.Header.Get(adminProtocolHeader); got != test.wantProtocol {
				t.Fatalf("X-Admin-Protocol = %q, want %q", got, test.wantProtocol)
			}
			if got := response.Header.Get("Content-Type"); got != ASN1MediaType {
				t.Fatalf("Content-Type = %q, want %q", got, ASN1MediaType)
			}
			if response.Close {
				t.Fatalf("response Close = true, want a reusable keep-alive connection")
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			// With nothing queued the eIM answers GetEimPackageResponse ->
			// eimPackageError(1), noEimPackageAvailable.
			want := []byte{0xbf, 0x4f, 0x03, 0x02, 0x01, 0x01}
			if !bytes.Equal(body, want) {
				t.Fatalf("body = %x, want %x", body, want)
			}
		})
	}
}

// TestASN1AndJSONBindingsStoreTheSameResult is the regression the Plugfest
// board needed: a getEimPackage / provideEimPackageResult exchange must leave
// identical state behind whether the IPA speaks the ASN.1 or the JSON binding.
func TestASN1AndJSONBindingsStoreTheSameResult(t *testing.T) {
	t.Parallel()

	transactionID := []byte{0x10, 0x20, 0x30, 0x40}
	bindings := map[string]func(t *testing.T, server *httptest.Server, eid []byte, provideDER []byte) []byte{
		"asn1": exchangeOverASN1Binding,
		"json": exchangeOverJSONBinding,
	}

	// storedState is what the eIM must end up with regardless of binding: the
	// operation outcome, the recorded result bytes, and the applied PSMO state.
	type storedState struct {
		Status   storage.OperationStatus
		Result   []byte
		Profiles []storage.ProfileState
	}

	observed := make(map[string]storedState, len(bindings))
	for name, exchange := range bindings {
		eid := testEID(0x66)
		eidKey := hex.EncodeToString(eid)
		ctx := context.Background()
		store := memory.New()
		if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
			t.Fatalf("[%s] RegisterDevice() error = %v", name, err)
		}
		request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
		request.EuiccPackageSigned.EimTransactionID = cloneBytes(transactionID)
		if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
			EID:     eidKey,
			Kind:    storage.OperationEuiccPackage,
			Payload: encode(t, request),
		}); err != nil {
			t.Fatalf("[%s] EnqueueOperation() error = %v", name, err)
		}

		handler := NewHandler(store, storage.DefaultTenantID)
		handler.AllowUnverifiedEUICCPackageResults = true
		server := httptest.NewServer(handler.HTTPHandler())
		t.Cleanup(server.Close)

		result := sampleEuiccPackageResultForTag(14, 3, 0)
		result.Signed.Data.EimTransactionID = cloneBytes(transactionID)
		provideTLV := constructed(tagProvideResult,
			octetTLV(tagEID, eid),
			mustTLVFromDER(t, wrapBF51Choice(t, encode(t, result), 0)),
		)
		provideDER, err := provideTLV.MarshalBinary()
		if err != nil {
			t.Fatalf("[%s] MarshalBinary(provide) error = %v", name, err)
		}

		packageDER := exchange(t, server, eid, provideDER)
		if !bytes.Equal(packageDER, encode(t, request)) {
			t.Fatalf("[%s] delivered package = %x, want %x", name, packageDER, encode(t, request))
		}
		pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 10)
		if err != nil {
			t.Fatalf("[%s] FetchPendingOperations() error = %v", name, err)
		}
		if len(pending) != 0 {
			t.Fatalf("[%s] pending = %#v, want empty after provide", name, pending)
		}
		operations, err := store.ListOperations(ctx, storage.DefaultTenantID, eidKey, 10)
		if err != nil {
			t.Fatalf("[%s] ListOperations() error = %v", name, err)
		}
		if len(operations) != 1 {
			t.Fatalf("[%s] operations = %#v, want one", name, operations)
		}
		operationResult, err := store.GetOperationResult(ctx, storage.DefaultTenantID, operations[0].ID)
		if err != nil {
			t.Fatalf("[%s] GetOperationResult() error = %v", name, err)
		}
		profiles, err := store.ListProfileStates(ctx, storage.DefaultTenantID, eidKey)
		if err != nil {
			t.Fatalf("[%s] ListProfileStates() error = %v", name, err)
		}
		observed[name] = storedState{
			Status:   operationResult.Status,
			Result:   operationResult.Payload,
			Profiles: profiles,
		}
	}

	if !reflect.DeepEqual(observed["asn1"], observed["json"]) {
		t.Fatalf("ASN.1 binding stored %#v, JSON binding stored %#v", observed["asn1"], observed["json"])
	}
	if observed["asn1"].Status != storage.OperationDone {
		t.Fatalf("stored status = %q, want a completed eUICC package result", observed["asn1"].Status)
	}
}

// exchangeOverASN1Binding polls and provides on GSMAPathASN1, returning the DER
// of the delivered eUICC package request.
func exchangeOverASN1Binding(t *testing.T, server *httptest.Server, eid []byte, provideDER []byte) []byte {
	t.Helper()

	poll := postASN1(t, server, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid}))
	response := decodeGetResponse(t, poll)
	if response.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("poll kind = %v, want eUICC package request", response.Kind)
	}
	provide := postASN1(t, server, encode(t, &protocolasn1.ESipaMessageFromIpaToEim{Raw: mustTLVFromDER(t, provideDER)}))
	if ack := decodeProvideResultAck(t, provide); len(ack.SequenceNumbers) == 0 {
		t.Fatal("provideEimPackageResult returned no acknowledgements")
	}
	return encode(t, response.EuiccPackageRequest)
}

// exchangeOverJSONBinding runs the same exchange over the GSMA HTTP JSON paths.
func exchangeOverJSONBinding(t *testing.T, server *httptest.Server, eid []byte, provideDER []byte) []byte {
	t.Helper()

	eidKey := hex.EncodeToString(eid)
	var poll gsmaGetEimPackageResponse
	postJSON(t, server, GSMAPathGetEimPackage, map[string]string{"eidValue": eidKey}, &poll)
	if poll.EuiccPackageRequest == "" {
		t.Fatalf("getEimPackage JSON = %#v, want euiccPackageRequest", poll)
	}
	packageDER, err := base64.StdEncoding.DecodeString(poll.EuiccPackageRequest)
	if err != nil {
		t.Fatalf("decode euiccPackageRequest error = %v", err)
	}
	var provide gsmaProvideResponse
	postJSON(t, server, GSMAPathProvideEimPackageResult, map[string]string{
		"eidValue":         eidKey,
		"eimPackageResult": base64.StdEncoding.EncodeToString(provideDER),
	}, &provide)
	if provide.EimAcknowledgements == "" {
		t.Fatalf("provideEimPackageResult JSON = %#v, want eimAcknowledgements", provide)
	}
	return packageDER
}

func postASN1(t *testing.T, server *httptest.Server, payload []byte) []byte {
	t.Helper()

	response, err := server.Client().Post(server.URL+GSMAPathASN1, ASN1MediaType, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST %s error = %v", GSMAPathASN1, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, body %s", response.Status, body)
	}
	return body
}

func postJSON(t *testing.T, server *httptest.Server, path string, request map[string]string, out any) {
	t.Helper()

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", path, err)
	}
	response, err := server.Client().Post(server.URL+path, GSMAJSONMediaType+";charset=UTF-8", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s error = %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %s", path, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		t.Fatalf("decode %s response error = %v", path, err)
	}
}
