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
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
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

var nextMockNotificationSequence atomic.Int64

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
	notifications := getJSON[notificationsResponse](t, server, "/v1/devices/"+testEID+"/notifications", http.StatusOK)
	if len(notifications.Notifications) != 1 || notifications.Notifications[0].Kind != "install" || notifications.Notifications[0].PayloadBase64 == "" {
		t.Fatalf("notifications = %#v, want one persisted install notification", notifications)
	}
	result := getJSON[operationResultResponse](t, server, "/v1/operations/"+itoa(queued.Operations[0].ID), http.StatusOK)
	if result.Operation.Status != string(storage.OperationDone) || result.Result == nil {
		t.Fatalf("operation result = %#v, want done result", result)
	}
}

func TestEUICCDataEndpointCompletesThroughMockIPA(t *testing.T) {
	t.Parallel()

	store := memory.New()
	server := newTestServer(t, store, DefaultTenantResolver{})

	queued := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/euicc-data/fetch", map[string]any{
		"tagListHex":                  "bf20bf22bf2da8",
		"notificationSeqNumber":       7,
		"euiccPackageResultSeqNumber": 9,
	}, http.StatusAccepted)
	if len(queued.Operations) != 1 {
		t.Fatalf("queued operations = %#v, want one", queued.Operations)
	}

	runMockIPAOnce(t, server)

	data := getJSON[euiccDataResponse](t, server, "/v1/devices/"+testEID+"/euicc-data", http.StatusOK)
	if data.DefaultSMDPAddress != "smdp.example" || data.EUICCInfo1Base64 == "" || data.IPACapabilitiesBase64 == "" {
		t.Fatalf("eUICC data = %#v, want SMDP, eUICCInfo1, and IPA capabilities", data)
	}
	if len(data.CertificateIdentifiers) != 3 {
		t.Fatalf("certificate identifiers = %#v, want CI identifiers from eUICCInfo1/2", data.CertificateIdentifiers)
	}
	if len(data.Profiles) != 1 || data.Profiles[0].ICCID != "89101122334455" || !data.Profiles[0].IsEnabled {
		t.Fatalf("profiles = %#v, want enabled mock profile", data.Profiles)
	}
	assertOperationDone(t, server, queued.Operations[0].ID)
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
	notifications := getJSON[notificationsResponse](t, server, "/v1/devices/"+testEID+"/notifications", http.StatusOK)
	gotKinds := make([]string, 0, len(notifications.Notifications))
	for _, notification := range notifications.Notifications {
		gotKinds = append(gotKinds, notification.Kind)
		if notification.SequenceNumber <= 0 || notification.PayloadBase64 == "" {
			t.Fatalf("notification = %#v, want sequence and payload", notification)
		}
	}
	if !reflect.DeepEqual(gotKinds, []string{"enable", "disable", "delete"}) {
		t.Fatalf("notification kinds = %#v, want enable/disable/delete", gotKinds)
	}
}

func TestEnableProfileQueuesRollbackFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		body         any
		wantRollback bool
	}{
		{name: "empty body", body: nil, wantRollback: false},
		{name: "field absent", body: map[string]any{}, wantRollback: false},
		{name: "rollback false", body: map[string]any{"rollback": false}, wantRollback: false},
		{name: "rollback true", body: map[string]any{"rollback": true}, wantRollback: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := memory.New()
			server := newTestServer(t, store, DefaultTenantResolver{})
			postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/"+testICCID+"/enable", tt.body, http.StatusAccepted)

			pending, err := store.FetchPendingOperations(context.Background(), storage.DefaultTenantID, testEID, 1)
			if err != nil {
				t.Fatalf("FetchPendingOperations() error = %v", err)
			}
			if len(pending) != 1 {
				t.Fatalf("pending operations = %d, want 1", len(pending))
			}
			var request protocolasn1.EuiccPackageRequest
			if err := protocolasn1.Decode(pending[0].Payload, &request); err != nil {
				t.Fatalf("Decode(EuiccPackageRequest) error = %v", err)
			}
			psmos := request.EuiccPackageSigned.EuiccPackage.PSMOs
			if len(psmos) != 1 || psmos[0].Operation != protocolasn1.PsmoEnable {
				t.Fatalf("queued PSMOs = %#v, want one enable operation", psmos)
			}
			if psmos[0].RollbackFlag != tt.wantRollback {
				t.Fatalf("RollbackFlag = %v, want %v", psmos[0].RollbackFlag, tt.wantRollback)
			}
		})
	}
}

func TestPSMOEndpointsCompleteThroughMockIPA(t *testing.T) {
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

	list := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/list", nil, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, list.Operations[0].ID)
	assertProfileFallback(t, server, testICCID, true)

	setFallback := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/"+testICCID+"/fallback", nil, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, setFallback.Operations[0].ID)
	assertProfileFallback(t, server, testICCID, true)

	unsetResponse := doRequest(t, server, http.MethodDelete, "/v1/devices/"+testEID+"/profiles/fallback", nil)
	if unsetResponse.Code != http.StatusAccepted {
		t.Fatalf("DELETE fallback status = %d body = %s, want %d", unsetResponse.Code, unsetResponse.Body.String(), http.StatusAccepted)
	}
	var unset enqueueResponse
	if err := json.NewDecoder(unsetResponse.Body).Decode(&unset); err != nil {
		t.Fatalf("Decode(unset fallback) error = %v", err)
	}
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, unset.Operations[0].ID)
	assertProfileFallback(t, server, testICCID, false)

	configure := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/immediate-enable", map[string]any{
		"immediateEnableFlag": true,
		"defaultSmdpOid":      "1.2.840.113549",
		"defaultSmdpAddress":  "smdp.example",
	}, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, configure.Operations[0].ID)

	getRAT := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/get-rat", nil, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, getRAT.Operations[0].ID)

	setDefault := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/default-dp-address", map[string]any{
		"defaultDpAddress": "smdp.example",
	}, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, setDefault.Operations[0].ID)
}

func TestEIMConfigurationEndpointsCompleteThroughMockIPA(t *testing.T) {
	t.Parallel()

	store := memory.New()
	server := newTestServer(t, store, DefaultTenantResolver{})

	add := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/eims", map[string]any{
		"eimFqdn":      "test.eim",
		"counterValue": 1,
	}, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, add.Operations[0].ID)
	assertAssociatedEIMState(t, server, "test.eim", 1, 1)

	update := putJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/eims/test.eim", map[string]any{
		"eimFqdn":      "test.eim",
		"counterValue": 2,
	}, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, update.Operations[0].ID)
	assertAssociatedEIMState(t, server, "test.eim", 2, 1)

	list := postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/eims/list", nil, http.StatusAccepted)
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, list.Operations[0].ID)

	deleteResponse := doRequest(t, server, http.MethodDelete, "/v1/devices/"+testEID+"/eims/test.eim", nil)
	if deleteResponse.Code != http.StatusAccepted {
		t.Fatalf("DELETE eIM status = %d body = %s, want %d", deleteResponse.Code, deleteResponse.Body.String(), http.StatusAccepted)
	}
	var deleted enqueueResponse
	if err := json.NewDecoder(deleteResponse.Body).Decode(&deleted); err != nil {
		t.Fatalf("Decode(delete eIM) error = %v", err)
	}
	runMockIPAOnce(t, server)
	assertOperationDone(t, server, deleted.Operations[0].ID)
	status := getJSON[eimStatusResponse](t, server, "/v1/devices/"+testEID+"/eims", http.StatusOK)
	if len(status.EIMs) != 0 {
		t.Fatalf("associated eIMs after delete = %#v, want none", status.EIMs)
	}
	if !status.BootstrapAllowed {
		t.Fatalf("bootstrapAllowed = false after last eIM delete, want true")
	}
}

func TestInitialEIMBootstrapEndpoints(t *testing.T) {
	t.Parallel()

	store := memory.New()
	server := newTestServer(t, store, DefaultTenantResolver{})

	missingFQDN, err := json.Marshal(map[string]any{"counterValue": 1})
	if err != nil {
		t.Fatalf("Marshal(missing FQDN) error = %v", err)
	}
	response := doRequest(t, server, http.MethodPost, "/v1/eims/initial-configuration", bytes.NewReader(missingFQDN))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("initial config without eimFqdn status = %d body = %s, want %d", response.Code, response.Body.String(), http.StatusBadRequest)
	}

	config := postJSON[eimConfigurationResponse](t, server, "/v1/eims/initial-configuration", map[string]any{
		"eimFqdn":      "test.eim",
		"counterValue": 1,
	}, http.StatusOK)
	if config.EIMID != "test.eim" || config.Config.EIMFQDN != "test.eim" || config.Config.CounterValue == nil || *config.Config.CounterValue != 1 || config.PayloadBase64 == "" {
		t.Fatalf("initial config response = %#v, want provisioning-ready test.eim config", config)
	}

	association := postJSON[initialEIMAssociationResponse](t, server, "/v1/devices/"+testEID+"/eims/initial-association", map[string]any{
		"associationToken": 42,
	}, http.StatusOK)
	if association.BootstrapAllowed || association.EIM.AssociationToken == nil || *association.EIM.AssociationToken != 42 {
		t.Fatalf("initial association response = %#v, want token 42 and bootstrap disabled", association)
	}
	assertAssociatedEIMState(t, server, "test.eim", 1, 42)
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
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/"+testICCID+"/fallback", nil, http.StatusAccepted)
	fallbackDeleteResponse := doRequest(t, server, http.MethodDelete, "/v1/devices/"+testEID+"/profiles/fallback", nil)
	if fallbackDeleteResponse.Code != http.StatusAccepted {
		t.Fatalf("DELETE fallback status = %d body = %s, want %d", fallbackDeleteResponse.Code, fallbackDeleteResponse.Body.String(), http.StatusAccepted)
	}
	deleteResponse := doRequest(t, server, http.MethodDelete, "/v1/devices/"+testEID+"/profiles/"+testICCID, nil)
	if deleteResponse.Code != http.StatusAccepted {
		t.Fatalf("DELETE status = %d body = %s, want %d", deleteResponse.Code, deleteResponse.Body.String(), http.StatusAccepted)
	}
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/list", nil, http.StatusAccepted)
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/get-rat", nil, http.StatusAccepted)
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/immediate-enable", map[string]any{"immediateEnableFlag": true}, http.StatusAccepted)
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/profiles/default-dp-address", map[string]any{"defaultDpAddress": "smdp.example"}, http.StatusAccepted)
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/eims", map[string]any{"counterValue": 1}, http.StatusAccepted)
	putJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/eims/test.eim", map[string]any{"counterValue": 2}, http.StatusAccepted)
	eimDeleteResponse := doRequest(t, server, http.MethodDelete, "/v1/devices/"+testEID+"/eims/test.eim", nil)
	if eimDeleteResponse.Code != http.StatusAccepted {
		t.Fatalf("DELETE eIM status = %d body = %s, want %d", eimDeleteResponse.Code, eimDeleteResponse.Body.String(), http.StatusAccepted)
	}
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/eims/list", nil, http.StatusAccepted)
	postJSON[enqueueResponse](t, server, "/v1/devices/"+testEID+"/euicc-data/fetch", nil, http.StatusAccepted)
	if err := store.SetEUICCState(context.Background(), storage.DefaultTenantID, storage.EUICCState{
		EID:                testEID,
		DefaultSMDPAddress: "smdp.example",
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	getJSON[euiccDataResponse](t, server, "/v1/devices/"+testEID+"/euicc-data", http.StatusOK)
	getJSON[eimStatusResponse](t, server, "/v1/devices/"+testEID+"/eims", http.StatusOK)
	getJSON[statusResponse](t, server, "/v1/devices/"+testEID+"/status", http.StatusOK)
	getJSON[operationResultResponse](t, server, "/v1/operations/"+itoa(queued.Operations[0].ID), http.StatusOK)

	if got := resolver.calls.Load(); got != 19 {
		t.Fatalf("tenant resolver calls = %d, want 19", got)
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
	esipaHandler := esipa.NewHandler(store, storage.DefaultTenantID)
	esipaHandler.AllowUnverifiedEUICCPackageResults = true
	root.Handle(esipa.DefaultPath, esipaHandler)
	server := httptest.NewServer(root)
	t.Cleanup(server.Close)
	return server
}

func runMockIPAOnce(t *testing.T, server *httptest.Server) {
	t.Helper()
	runner := mockipa.Runner{
		Client:                   mockipa.Client{Endpoint: server.URL + esipa.DefaultPath, HTTPClient: server.Client()},
		Downloader:               mockipa.OfflineDownloader{},
		EID:                      mustEIDBytes(t, testEID),
		Once:                     true,
		NextNotificationSequence: nextMockNotificationSequence.Add(1),
		Logger:                   slog.New(slog.NewTextHandler(testWriter{t: t}, nil)),
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

func assertProfileFallback(t *testing.T, server *httptest.Server, iccid string, fallback bool) {
	t.Helper()
	status := getJSON[statusResponse](t, server, "/v1/devices/"+testEID+"/status", http.StatusOK)
	for _, profile := range status.Profiles {
		if profile.ICCID == iccid {
			if profile.IsFallback != fallback {
				t.Fatalf("profile %s fallback = %v, want %v", iccid, profile.IsFallback, fallback)
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

func assertAssociatedEIMState(t *testing.T, server *httptest.Server, eimID string, counter int64, associationToken int64) {
	t.Helper()
	status := getJSON[eimStatusResponse](t, server, "/v1/devices/"+testEID+"/eims", http.StatusOK)
	for _, eim := range status.EIMs {
		if eim.EIMID == eimID {
			if eim.CounterValue == nil || *eim.CounterValue != counter {
				t.Fatalf("eIM %s counter = %#v, want %d", eimID, eim.CounterValue, counter)
			}
			if eim.AssociationToken == nil || *eim.AssociationToken != associationToken {
				t.Fatalf("eIM %s association token = %#v, want %d", eimID, eim.AssociationToken, associationToken)
			}
			return
		}
	}
	t.Fatalf("eIM %s not found in status %#v", eimID, status)
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

func putJSON[T any](t *testing.T, server *httptest.Server, path string, body any, wantStatus int) T {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	response := doRequest(t, server, http.MethodPut, path, bytes.NewReader(payload))
	if response.Code != wantStatus {
		t.Fatalf("PUT %s status = %d body = %s, want %d", path, response.Code, response.Body.String(), wantStatus)
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
