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
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/ipadata"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestGSMAJSONGetProvideAndHandleNotification(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x61)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	transactionID := []byte{0x10, 0x20, 0x30, 0x40}
	request.EuiccPackageSigned.EimTransactionID = cloneBytes(transactionID)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, request),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	handler := NewHandler(store, storage.DefaultTenantID)
	handler.AllowUnverifiedEUICCPackageResults = true
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)

	getBody, _ := json.Marshal(map[string]string{"eidValue": eidKey})
	getReq, err := http.NewRequest(http.MethodPost, server.URL+GSMAPathGetEimPackage, bytes.NewReader(getBody))
	if err != nil {
		t.Fatalf("NewRequest(get) error = %v", err)
	}
	getReq.Header.Set("Content-Type", GSMAJSONMediaType+";charset=UTF-8")
	getReq.Header.Set(adminProtocolHeader, "gsma/rsp/v2.1.0")
	getResp, err := server.Client().Do(getReq)
	if err != nil {
		t.Fatalf("getEimPackage error = %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("getEimPackage status = %d", getResp.StatusCode)
	}
	if got := getResp.Header.Get(adminProtocolHeader); got != "gsma/rsp/v2.1.0" {
		t.Fatalf("X-Admin-Protocol = %q, want request echo", got)
	}
	raw, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("read get body error = %v", err)
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		t.Fatalf("decode get object error = %v", err)
	}
	if _, ok := nested["getEimPackageResponse"]; ok {
		t.Fatalf("get response nested under getEimPackageResponse: %s", raw)
	}
	var getJSON gsmaGetEimPackageResponse
	if err := json.Unmarshal(raw, &getJSON); err != nil {
		t.Fatalf("decode get JSON error = %v", err)
	}
	if getJSON.EimPackageError != 0 || getJSON.EuiccPackageRequest == "" {
		t.Fatalf("get JSON = %#v, want success with euiccPackageRequest", getJSON)
	}
	if getJSON.Header.FunctionExecutionStatus.Status != "Executed-Success" {
		t.Fatalf("get header status = %q", getJSON.Header.FunctionExecutionStatus.Status)
	}

	result := sampleEuiccPackageResultForTag(14, 3, 0)
	result.Signed.Data.EimTransactionID = cloneBytes(transactionID)
	resultDER := encode(t, result)
	choiceDER := wrapBF51Choice(t, resultDER, 0)
	provideTLV := constructed(tagProvideResult,
		octetTLV(tagEID, eid),
		mustTLVFromDER(t, choiceDER),
	)
	provideDER, err := provideTLV.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(provide) error = %v", err)
	}

	provideBody, _ := json.Marshal(map[string]string{
		"eidValue":         eidKey,
		"eimPackageResult": base64.StdEncoding.EncodeToString(provideDER),
	})
	provideReq, err := http.NewRequest(http.MethodPost, server.URL+GSMAPathProvideEimPackageResult, bytes.NewReader(provideBody))
	if err != nil {
		t.Fatalf("NewRequest(provide) error = %v", err)
	}
	provideReq.Header.Set("Content-Type", GSMAJSONMediaType)
	provideResp, err := server.Client().Do(provideReq)
	if err != nil {
		t.Fatalf("provideEimPackageResult error = %v", err)
	}
	defer provideResp.Body.Close()
	if provideResp.StatusCode != http.StatusOK {
		t.Fatalf("provide status = %d", provideResp.StatusCode)
	}

	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %#v, want empty after provide", pending)
	}
}

func TestGSMAJSONHandleNotificationProvideWithoutEIDValue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x62)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := []byte{0xab, 0xcd}
	request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	request.EuiccPackageSigned.EimTransactionID = cloneBytes(transactionID)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, request),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	handler := NewHandler(store, storage.DefaultTenantID)
	handler.AllowUnverifiedEUICCPackageResults = true
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)

	result := sampleEuiccPackageResultForTag(9, 3, 0)
	result.Signed.Data.EimTransactionID = cloneBytes(transactionID)
	provide := &protocolasn1.ProvideEimPackageResult{
		EID: eid,
		EimPackageResult: protocolasn1.EimPackageResult{
			Raw: mustTLV(t, result),
		},
	}
	provideDER := encode(t, provide)
	body, _ := json.Marshal(map[string]string{
		"provideEimPackageResult": base64.StdEncoding.EncodeToString(provideDER),
	})
	req, err := http.NewRequest(http.MethodPost, server.URL+GSMAPathHandleNotification, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Content-Type", GSMAJSONMediaType)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("handleNotification error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %#v, want empty", pending)
	}
}

func TestGSMAJSONGetIpaEuiccDataRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x64)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if _, err := ipadata.EnqueueRequest(ctx, store, storage.DefaultTenantID, eidKey, ipadata.RequestInput{
		TagList: []byte{0xbf, 0x20},
	}); err != nil {
		t.Fatalf("EnqueueRequest() error = %v", err)
	}

	handler := NewHandler(store, storage.DefaultTenantID)
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)

	getBody, _ := json.Marshal(map[string]string{"eidValue": eidKey})
	req, err := http.NewRequest(http.MethodPost, server.URL+GSMAPathGetEimPackage, bytes.NewReader(getBody))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Content-Type", GSMAJSONMediaType)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("getEimPackage error = %v", err)
	}
	defer resp.Body.Close()
	var getJSON gsmaGetEimPackageResponse
	if err := json.NewDecoder(resp.Body).Decode(&getJSON); err != nil {
		t.Fatalf("decode JSON error = %v", err)
	}
	if getJSON.IpaEuiccDataRequest == "" || getJSON.EuiccPackageRequest != "" {
		t.Fatalf("get JSON = %#v, want ipaEuiccDataRequest only", getJSON)
	}
}

func TestGSMAJSONProvideRecoversEIDFromTransactionID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x65)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	request := samplePSMOEuiccPackageRequest(eid, protocolasn1.PsmoEnable, 3)
	request.EuiccPackageSigned.EimTransactionID = cloneBytes(transactionID)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, request),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	handler := NewHandler(store, storage.DefaultTenantID)
	handler.AllowUnverifiedEUICCPackageResults = true
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)

	result := sampleEuiccPackageResultForTag(3, 3, 0)
	result.Signed.Data.EimTransactionID = cloneBytes(transactionID)
	// BF51 only — no outer BF50 EID and no eidValue in JSON.
	resultDER := encode(t, result)
	body, _ := json.Marshal(map[string]string{
		"eimPackageResult": base64.StdEncoding.EncodeToString(resultDER),
	})
	req, err := http.NewRequest(http.MethodPost, server.URL+GSMAPathProvideEimPackageResult, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Content-Type", GSMAJSONMediaType)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("provide error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %#v, want empty after EID recovery", pending)
	}
}

func wrapBF51Choice(t *testing.T, bf51DER []byte, arm uint64) []byte {
	t.Helper()
	tlv := mustTLVFromDER(t, bf51DER)
	if len(tlv.Children) != 1 {
		t.Fatalf("BF51 children = %d, want 1", len(tlv.Children))
	}
	wrapped := constructed(tagEuiccPackage,
		constructed(bertlv.ContextSpecific.Constructed(arm), tlv.Children[0].Children...),
	)
	out, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(CHOICE) error = %v", err)
	}
	return out
}
