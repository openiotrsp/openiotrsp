package mockipa

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http/httptest"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/esipa"
	"github.com/openiotrsp/openiotrsp/ipadata"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

type testProfileDownloader struct{}

func (testProfileDownloader) Download(_ context.Context, activation profiledownload.ActivationCode) (DownloadResult, error) {
	return DownloadResult{
		ProfileID: activation.ProfileID(),
		SMDP:      activation.SMDPAddress,
		Offline:   true,
	}, nil
}

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

	fixture := requireSGP26SoftwareFixture(t)
	server := httptest.NewServer(esipa.NewHTTPHandler(store, storage.DefaultTenantID))
	defer server.Close()

	runner := Runner{
		Client: Client{Transport: HTTPTransport{
			Endpoint:   server.URL + esipa.DefaultPath,
			HTTPClient: server.Client(),
		}},
		Downloader: testProfileDownloader{},
		Fixture:    fixture,
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
	notifications, err := store.ListNotifications(ctx, storage.DefaultTenantID, eid)
	if err != nil {
		t.Fatalf("ListNotifications() error = %v", err)
	}
	if len(notifications) != 1 || notifications[0].Kind != "install" || notifications[0].SequenceNumber != 1 {
		t.Fatalf("notifications = %#v, want install sequence 1", notifications)
	}
}

func TestRunnerNotificationAcknowledgementClearsOnlyAckedSequences(t *testing.T) {
	t.Parallel()

	eidBytes, err := hex.DecodeString("89049032000000000000000000000003")
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	runner := Runner{EID: eidBytes, Fixture: requireSGP26SoftwareFixture(t)}
	first, err := runner.queueNotification("enable")
	if err != nil {
		t.Fatalf("queueNotification(enable) error = %v", err)
	}
	second, err := runner.queueNotification("disable")
	if err != nil {
		t.Fatalf("queueNotification(disable) error = %v", err)
	}

	pending := runner.pendingNotificationTLVs()
	if len(pending) != 2 {
		t.Fatalf("pending notifications before ack = %d, want 2", len(pending))
	}

	runner.acknowledgeNotifications(&protocolasn1.EimAcknowledgements{
		SequenceNumbers: []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(first.SequenceNumber)},
	})
	pending = runner.pendingNotificationTLVs()
	if len(pending) != 1 || runner.pendingNotifications[0].SequenceNumber != second.SequenceNumber {
		t.Fatalf("pending after first ack = %#v, want only sequence %d", runner.pendingNotifications, second.SequenceNumber)
	}

	runner.acknowledgeNotifications(&protocolasn1.EimAcknowledgements{
		SequenceNumbers: []protocolasn1.SequenceNumber{99},
	})
	pending = runner.pendingNotificationTLVs()
	if len(pending) != 1 || runner.pendingNotifications[0].SequenceNumber != second.SequenceNumber {
		t.Fatalf("pending after unrelated ack = %#v, want sequence %d still available", runner.pendingNotifications, second.SequenceNumber)
	}

	runner.acknowledgeNotifications(&protocolasn1.EimAcknowledgements{
		SequenceNumbers: []protocolasn1.SequenceNumber{protocolasn1.SequenceNumber(second.SequenceNumber)},
	})
	pending = runner.pendingNotificationTLVs()
	if len(pending) != 0 {
		t.Fatalf("pending after all acked = %d, want 0", len(pending))
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

	fixture := requireSGP26SoftwareFixture(t)
	server := httptest.NewServer(esipa.NewHTTPHandler(store, storage.DefaultTenantID))
	defer server.Close()

	runner := Runner{
		Client: Client{Transport: HTTPTransport{
			Endpoint:   server.URL + esipa.DefaultPath,
			HTTPClient: server.Client(),
		}},
		Fixture: fixture,
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
	if len(state.EUICCInfo1) == 0 {
		t.Fatalf("eUICC state = %#v, want EUICCInfo1 from mock IPA data", state)
	}
	if runner.Fixture != nil && len(state.CertificateIdentifiers) == 0 {
		t.Fatalf("eUICC state = %#v, want certificate identifiers from fixture-backed IPA data", state)
	}
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
