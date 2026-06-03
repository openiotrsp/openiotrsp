package mockipa

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/openiotrsp/openiotrsp/esipa"
	"github.com/openiotrsp/openiotrsp/ipadata"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestRunnerCompletesProfileDownloadTrigger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "89049032000000000000000000000001"
	eidBytes, err := hex.DecodeString(eid)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	trigger, err := profiledownload.NewActivationCodeTrigger("1$smdpp.test.rsp.sysmocom.de$TS48V1-B-UNIQUE", []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eid, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}

	server := httptest.NewServer(esipa.NewHTTPHandler(store, storage.DefaultTenantID))
	defer server.Close()

	runner := Runner{
		Client:     Client{Endpoint: server.URL + esipa.DefaultPath, HTTPClient: server.Client()},
		Downloader: OfflineDownloader{},
		EID:        eidBytes,
		Once:       true,
		Logger:     slog.New(slog.NewTextHandler(testWriter{t: t}, nil)),
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eid, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending operations = %#v, want none", pending)
	}
	state, err := store.GetProfileState(ctx, storage.DefaultTenantID, eid, "TS48V1-B-UNIQUE")
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if !state.IsEnabled || state.SMDPAddress != "smdpp.test.rsp.sysmocom.de" {
		t.Fatalf("profile state = %#v, want enabled sysmocom profile", state)
	}
}

func TestRunnerCompletesIpaEuiccDataRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "89049032000000000000000000000002"
	eidBytes, err := hex.DecodeString(eid)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	seq := int64(3)
	if _, err := ipadata.EnqueueRequest(ctx, store, storage.DefaultTenantID, eid, ipadata.RequestInput{
		TagList:                     []byte{0x5a, 0xbf, 0x20, 0xbf, 0x2d},
		EuiccPackageResultSeqNumber: &seq,
		EimTransactionID:            []byte{0x01, 0x02},
	}); err != nil {
		t.Fatalf("EnqueueRequest() error = %v", err)
	}

	server := httptest.NewServer(esipa.NewHTTPHandler(store, storage.DefaultTenantID))
	defer server.Close()

	runner := Runner{
		Client: Client{Endpoint: server.URL + esipa.DefaultPath, HTTPClient: server.Client()},
		EID:    eidBytes,
		Once:   true,
		Logger: slog.New(slog.NewTextHandler(testWriter{t: t}, nil)),
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eid, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending operations = %#v, want none", pending)
	}
	state, err := store.GetEUICCState(ctx, storage.DefaultTenantID, eid)
	if err != nil {
		t.Fatalf("GetEUICCState() error = %v", err)
	}
	if state.DefaultSMDPAddress != "smdp.example" || len(state.CertificateIdentifiers) == 0 {
		t.Fatalf("eUICC state = %#v, want mock IPA data", state)
	}
	profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eid, "89101122334455")
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if !profile.IsEnabled {
		t.Fatalf("profile = %#v, want enabled", profile)
	}
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
