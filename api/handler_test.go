package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/openiotrsp/openiotrsp/esipa"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	"github.com/openiotrsp/openiotrsp/mockipa"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

const (
	testEID   = "89049032000000000000000000000001"
	testICCID = "89101122334455"
)

func TestProfileDownloadEndpointCompletesThroughMockIPA(t *testing.T) {
	t.Parallel()

	store := memory.New()
	server := newTestServer(t, store, DefaultTenantResolver{})

	queued := postJSON[enqueueResponse](t, server, "/v1/profile-downloads", map[string]any{
		"eid":            testEID,
		"activationCode": "1$smdpp.test.rsp.sysmocom.de$TS48V1-B-UNIQUE",
	}, http.StatusAccepted)
	if len(queued.Operations) != 1 {
		t.Fatalf("queued operations = %#v, want one", queued.Operations)
	}

	runMockIPAOnce(t, server)

	status := getJSON[statusResponse](t, server, "/v1/devices/"+testEID+"/status", http.StatusOK)
	if len(status.Profiles) != 1 || status.Profiles[0].ICCID != "TS48V1-B-UNIQUE" || !status.Profiles[0].IsEnabled {
		t.Fatalf("status = %#v, want enabled downloaded profile", status)
	}
	result := getJSON[operationResultResponse](t, server, "/v1/operations/"+itoa(queued.Operations[0].ID), http.StatusOK)
	if result.Operation.Status != string(storage.OperationDone) || result.Result == nil {
		t.Fatalf("operation result = %#v, want done result", result)
	}
}

func TestProfileLifecycleEndpointsCompleteThroughMockIPA(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: testEID}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:       testEID,
		ICCID:     testICCID,
		IsEnabled: false,
	}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}
	server := newTestServer(t, store, DefaultTenantResolver{})

	enable := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/"+testICCID+"/enable", nil, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertProfileState(t, server, testICCID, true)
	assertOperationDone(t, server, enable.Operations[0].ID)

	disable := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/"+testICCID+"/disable", nil, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertProfileState(t, server, testICCID, false)
	assertOperationDone(t, server, disable.Operations[0].ID)

	deleteResponse := doRequest(t, server, http.MethodDelete, "/v1/devices/"+testEID+"/profiles/"+testICCID, nil)
	if deleteResponse.Code != http.StatusAccepted {
		t.Fatalf("DELETE status = %d body = %s, want %d", deleteResponse.Code, deleteResponse.Body.String(), http.StatusAccepted)
	}
	runMockIPAOnce(t, server)
	status := getJSON[statusResponse](t, server, "/v1/devices/"+testEID+"/status", http.StatusOK)
	if len(status.Profiles) != 0 {
		t.Fatalf("profiles after delete = %#v, want none", status.Profiles)
	}
}

func TestDefaultTenantResolverQueuesUnderDefaultTenant(t *testing.T) {
	t.Parallel()

	store := memory.New()
	server := newTestServer(t, store, DefaultTenantResolver{})
	postJSON[enqueueResponse](t, server, "/v1/profile-downloads", map[string]any{
		"eid":            testEID,
		"activationCode": "1$smdpp.example$match",
	}, http.StatusAccepted)

	pending, err := store.FetchPendingOperations(context.Background(), storage.DefaultTenantID, testEID, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations(default tenant) error = %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("default tenant pending = %d, want 1", len(pending))
	}
}

func TestEveryEndpointResolvesTenant(t *testing.T) {
	t.Parallel()

	store := memory.New()
	resolver := &recordingResolver{tenantID: storage.DefaultTenantID}
	server := newTestServer(t, store, resolver)
	queued := postJSON[enqueueResponse](t, server, "/v1/profile-downloads", map[string]any{
		"eid":            testEID,
		"activationCode": "1$smdpp.example$match",
	}, http.StatusAccepted)
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/"+testICCID+"/enable", nil, http.StatusAccepted)
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/"+testICCID+"/disable", nil, http.StatusAccepted)
	deleteResponse := doRequest(t, server, http.MethodDelete, "/v1/devices/"+testEID+"/profiles/"+testICCID, nil)
	if deleteResponse.Code != http.StatusAccepted {
		t.Fatalf("DELETE status = %d body = %s, want %d", deleteResponse.Code, deleteResponse.Body.String(), http.StatusAccepted)
	}
	getJSON[statusResponse](t, server, "/v1/devices/"+testEID+"/status", http.StatusOK)
	getJSON[operationResultResponse](t, server, "/v1/operations/"+itoa(queued.Operations[0].ID), http.StatusOK)

	if got := resolver.calls.Load(); got != 6 {
		t.Fatalf("tenant resolver calls = %d, want 6", got)
	}
}

func newTestServer(t *testing.T, store storage.Store, resolver TenantResolver) *httptest.Server {
	t.Helper()
	apiHandler := NewHTTPHandler(store, resolver, &euiccpkg.Service{
		Store:  store,
		Signer: newTestSigner(t),
		EimID:  "test.eim",
	})
	root := http.NewServeMux()
	root.Handle("/v1/", apiHandler)
	root.Handle(esipa.DefaultPath, esipa.NewHandler(store, storage.DefaultTenantID))
	server := httptest.NewServer(root)
	t.Cleanup(server.Close)
	return server
}

func runMockIPAOnce(t *testing.T, server *httptest.Server) {
	t.Helper()
	runner := mockipa.Runner{
		Client:     mockipa.Client{Endpoint: server.URL + esipa.DefaultPath, HTTPClient: server.Client()},
		Downloader: mockipa.OfflineDownloader{},
		EID:        mustEIDBytes(t, testEID),
		Once:       true,
		Logger:     slog.New(slog.NewTextHandler(testWriter{t: t}, nil)),
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("mock IPA Run() error = %v", err)
	}
}

func assertProfileState(t *testing.T, server *httptest.Server, iccid string, enabled bool) {
	t.Helper()
	status := getJSON[statusResponse](t, server, "/v1/devices/"+testEID+"/status", http.StatusOK)
	for _, profile := range status.Profiles {
		if profile.ICCID == iccid {
			if profile.IsEnabled != enabled {
				t.Fatalf("profile %s enabled = %v, want %v", iccid, profile.IsEnabled, enabled)
			}
			return
		}
	}
	t.Fatalf("profile %s not found in status %#v", iccid, status)
}

func assertOperationDone(t *testing.T, server *httptest.Server, operationID int64) {
	t.Helper()
	result := getJSON[operationResultResponse](t, server, "/v1/operations/"+itoa(operationID), http.StatusOK)
	if result.Operation.Status != string(storage.OperationDone) || result.Result == nil {
		t.Fatalf("operation result = %#v, want done with result", result)
	}
}

func postJSON[T any](t *testing.T, server *httptest.Server, path string, body any, wantStatus int) T {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		reader = bytes.NewReader(payload)
	}
	response := doRequest(t, server, http.MethodPost, path, reader)
	if response.Code != wantStatus {
		t.Fatalf("POST %s status = %d body = %s, want %d", path, response.Code, response.Body.String(), wantStatus)
	}
	var out T
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatalf("Decode(%s) error = %v", path, err)
	}
	return out
}

func getJSON[T any](t *testing.T, server *httptest.Server, path string, wantStatus int) T {
	t.Helper()
	response := doRequest(t, server, http.MethodGet, path, nil)
	if response.Code != wantStatus {
		t.Fatalf("GET %s status = %d body = %s, want %d", path, response.Code, response.Body.String(), wantStatus)
	}
	var out T
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatalf("Decode(%s) error = %v", path, err)
	}
	return out
}

func doRequest(t *testing.T, server *httptest.Server, method string, path string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, server.URL+path, body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Config.Handler.ServeHTTP(response, request)
	return response
}

type recordingResolver struct {
	tenantID storage.TenantID
	calls    atomic.Int32
}

func (r *recordingResolver) ResolveTenant(ctx context.Context, _ *http.Request) (storage.TenantID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.calls.Add(1)
	return r.tenantID, nil
}

type testSigner struct {
	key *ecdsa.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return &testSigner{key: key}
}

func (s *testSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func (s *testSigner) PublicKey() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *testSigner) CertificateDER() []byte {
	return nil
}

func mustEIDBytes(t *testing.T, eid string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(eid)
	if err != nil {
		t.Fatalf("decode EID: %v", err)
	}
	return decoded
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
