package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
	piondtls "github.com/pion/dtls/v3"
	coapdtls "github.com/plgd-dev/go-coap/v3/dtls"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/net/blockwise"
	"github.com/plgd-dev/go-coap/v3/options"
)

const externalInteropEnv = "OPENIOTRSP_EXTERNAL_INTEROP"
const coapVerboseEnv = "OPENIOTRSP_COAP_VERBOSE"

func TestExternalCurlOpenSSLHTTPS(t *testing.T) {
	requireExternalInterop(t)
	curl := requireExternalTool(t, "curl")
	openssl := requireExternalTool(t, "openssl")

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x71)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	wantPackage := sampleEuiccPackageRequest(eid, 3)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, wantPackage),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	server := httptest.NewTLSServer(NewHandler(store, storage.DefaultTenantID).HTTPHandler())
	t.Cleanup(server.Close)

	requestPath := filepath.Join(t.TempDir(), "get-eim-package.der")
	responsePath := filepath.Join(t.TempDir(), "response.der")
	writeFile(t, requestPath, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid}))

	_ = runExternal(t, curl, "-fsS", "-k",
		"-X", http.MethodPost,
		"-H", "Content-Type: "+MediaType,
		"--data-binary", "@"+requestPath,
		"-o", responsePath,
		server.URL+DefaultPath,
	)
	_ = runExternal(t, openssl, "asn1parse", "-inform", "DER", "-in", responsePath)

	responseDER := readFile(t, responsePath)
	decoded := decodeGetResponse(t, responseDER)
	if decoded.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("curl response kind = %v, want eUICC package", decoded.Kind)
	}
	if !bytes.Equal(encode(t, decoded.EuiccPackageRequest), encode(t, wantPackage)) {
		t.Fatalf("curl response package mismatch")
	}
}

func TestExternalLibcoapDTLSRoundTrip(t *testing.T) {
	requireExternalInterop(t)
	coapClient := requireCoAPClient(t)

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x72)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	wantPackage := sampleEuiccPackageRequest(eid, 3)
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, wantPackage),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	responseDER := runExternalCoAPClient(t, coapClient, store, eid, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid}), 1024)
	decoded := decodeGetResponse(t, responseDER)
	if decoded.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("coap-client response kind = %v, want eUICC package", decoded.Kind)
	}
	if !bytes.Equal(encode(t, decoded.EuiccPackageRequest), encode(t, wantPackage)) {
		t.Fatalf("coap-client response package mismatch")
	}
}

func TestExternalLibcoapDTLSBlockwiseLargePackage(t *testing.T) {
	requireExternalInterop(t)
	coapClient := requireCoAPClient(t)

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x73)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	wantPackage := sampleEuiccPackageRequest(eid, 4096)
	t.Logf("expected large ESipa response size is %d bytes", len(encodeEnvelope(t, &protocolasn1.GetEimPackageResponse{
		Kind:                protocolasn1.GetEimPackageEuiccPackageRequest,
		EuiccPackageRequest: wantPackage,
	})))
	if _, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eidKey,
		Kind:    storage.OperationEuiccPackage,
		Payload: encode(t, wantPackage),
	}); err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	responseDER := runExternalCoAPClient(t, coapClient, store, eid, encodeEnvelope(t, &protocolasn1.GetEimPackageRequest{EID: eid}), 1024)
	decoded := decodeGetResponse(t, responseDER)
	if decoded.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
		t.Fatalf("coap-client blockwise response kind = %v, want eUICC package", decoded.Kind)
	}
	if !bytes.Equal(encode(t, decoded.EuiccPackageRequest), encode(t, wantPackage)) {
		t.Fatalf("coap-client blockwise package mismatch")
	}
}

func runExternalCoAPClient(t *testing.T, coapClient string, store storage.Store, eid []byte, requestDER []byte, blockSize int) []byte {
	t.Helper()

	const (
		pskIdentity = "openiotrsp"
		pskKey      = "openiotrsp-secret"
	)
	listener, err := coapnet.NewDTLSListener("udp", "127.0.0.1:0", coapnet.NewDTLSServerOptions(
		piondtls.WithPSK(func(identityHint []byte) ([]byte, error) {
			return []byte(pskKey), nil
		}),
		piondtls.WithPSKIdentityHint([]byte(pskIdentity)),
		piondtls.WithCipherSuites(piondtls.TLS_PSK_WITH_AES_128_CCM_8),
	))
	if err != nil {
		t.Fatalf("NewDTLSListener() error = %v", err)
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	server := coapdtls.NewServer(
		options.WithMux(handler.CoAPHandler()),
		options.WithMaxMessageSize(uint32(handler.maxMessageSize())),
		options.WithBlockwise(false, blockwise.SZX1024, time.Second),
	)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Logf("CoAP/DTLS server stopped with: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Log("CoAP/DTLS server did not stop within timeout")
		}
	})

	tempDir := t.TempDir()
	requestPath := filepath.Join(tempDir, "request.der")
	responsePath := filepath.Join(tempDir, "response.der")
	writeFile(t, requestPath, requestDER)
	uri := (&url.URL{
		Scheme: "coaps",
		Host:   listener.Addr().String(),
		Path:   DefaultPath,
	}).String()

	args := []string{
		"-m", "post",
		"-u", pskIdentity,
		"-k", pskKey,
		"-B", "5",
		"-f", requestPath,
		"-o", responsePath,
		uri,
	}
	if blockSize > 0 {
		args = append(args[:8], append([]string{"-b", fmt.Sprint(blockSize)}, args[8:]...)...)
	}
	if os.Getenv(coapVerboseEnv) == "1" {
		args = append([]string{"-v", "9"}, args...)
	}
	output := runExternal(t, coapClient, args...)
	if len(output) > 0 {
		t.Logf("%s output:\n%s", filepath.Base(coapClient), output)
	}
	response := readFile(t, responsePath)
	t.Logf("%s wrote %d response bytes", filepath.Base(coapClient), len(response))
	return response
}

func requireExternalTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed; skipping external interoperability check", name)
	}
	return path
}

func requireExternalInterop(t *testing.T) {
	t.Helper()
	if os.Getenv(externalInteropEnv) != "1" {
		t.Skipf("%s=1 is required for external interoperability checks", externalInteropEnv)
	}
}

func requireCoAPClient(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"coap-client", "coap-client-gnutls", "coap-client-openssl"} {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}
	t.Skip("coap-client is not installed; skipping external CoAP/DTLS interoperability check")
	return ""
}

func runExternal(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("%s timed out\n%s", name, output)
	}
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, output)
	}
	return output
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
