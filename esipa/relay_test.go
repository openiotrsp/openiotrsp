package esipa

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestRelayHandlerForwardsAndReturnsRawBERWithoutReencoding(t *testing.T) {
	t.Parallel()

	requestPayload := mustRelayHex(t, "bf398110830b6578616d706c652e636f6d8101ff")
	responsePayload := mustRelayHex(t, "bf3981058003010203")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: responsePayload},
		},
	}
	handler := &Handler{Relay: relay.New(transport)}
	request, err := DecodeRequest(requestPayload)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}

	response, err := handler.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("handle(relay) error = %v", err)
	}
	encoded, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("relay calls = %d, want 1", len(transport.calls))
	}
	if !bytes.Equal(transport.calls[0].payload, requestPayload) {
		t.Fatalf("relayed payload = %x, want exact request bytes %x", transport.calls[0].payload, requestPayload)
	}
	if !bytes.Equal(encoded, responsePayload) {
		t.Fatalf("encoded response = %x, want exact SM-DP+ bytes %x", encoded, responsePayload)
	}
}

func TestRelayHandleNotificationHTTPReturns204(t *testing.T) {
	t.Parallel()

	initRequest := mustRelayHex(t, "bf398110830b6578616d706c652e636f6d8101ff")
	initResponse := mustRelayHex(t, "bf39058003010203")
	requestPayload := mustRelayHex(t, "bf3d0d0c0b6578616d706c652e636f6d")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initResponse},
			relay.EndpointHandleNotification:     {NoContent: true},
		},
	}
	relayService := relay.New(transport)
	if _, err := relayService.InitiateAuthentication(context.Background(), initRequest); err != nil {
		t.Fatalf("InitiateAuthentication() error = %v", err)
	}
	transport.calls = nil
	server := httptest.NewServer((&Handler{Relay: relayService}).HTTPHandler())
	t.Cleanup(server.Close)

	response, err := server.Client().Post(server.URL+DefaultPath, MediaType, bytes.NewReader(requestPayload))
	if err != nil {
		t.Fatalf("POST relay notification error = %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if response.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("response = %s body %x, want empty 204", response.Status, body)
	}
	if len(transport.calls) != 1 || transport.calls[0].endpoint != relay.EndpointHandleNotification {
		t.Fatalf("relay calls = %#v, want one handleNotification call", transport.calls)
	}
	if !bytes.Equal(transport.calls[0].payload, requestPayload) {
		t.Fatalf("notification payload = %x, want %x", transport.calls[0].payload, requestPayload)
	}
}

func TestRelayConfiguredHandlerPersistsNotificationBeforeRelaySession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x65)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transport := &esipaRecordingTransport{}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relay.New(transport)
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)

	payload := encode(t, &protocolasn1.ESipaMessageFromIpaToEim{
		Raw: bertlv.NewChildren(tagHandleNotify,
			bertlv.NewChildren(tagNotificationList, samplePendingNotification(t, eid, 23, "install")),
		),
	})
	response, err := server.Client().Post(server.URL+DefaultPath, MediaType, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST notification error = %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("response = %s body %x, want 204", response.Status, body)
	}
	if len(transport.calls) != 0 {
		t.Fatalf("relay calls = %#v, want direct notification persistence before relay session", transport.calls)
	}
	notifications, err := store.ListNotifications(ctx, storage.DefaultTenantID, eidKey)
	if err != nil {
		t.Fatalf("ListNotifications() error = %v", err)
	}
	if len(notifications) != 1 || notifications[0].SequenceNumber != 23 || notifications[0].Kind != "install" {
		t.Fatalf("notifications = %#v, want install sequence 23", notifications)
	}
}

func TestRelayConfiguredHandlerPersistsLocalNotificationDuringRelaySession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x66)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	initRequest := mustRelayHex(t, "bf398110830b6578616d706c652e636f6d8101ff")
	initResponse := mustRelayHex(t, "bf39058003010203")
	transport := &esipaRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initResponse},
		},
	}
	relayService := relay.New(transport)
	if _, err := relayService.InitiateAuthentication(ctx, initRequest); err != nil {
		t.Fatalf("InitiateAuthentication() error = %v", err)
	}
	transport.calls = nil
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.Relay = relayService
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)

	payload := encode(t, &protocolasn1.ESipaMessageFromIpaToEim{
		Raw: bertlv.NewChildren(tagHandleNotify,
			bertlv.NewChildren(tagNotificationList, samplePendingNotification(t, eid, 24, "install")),
		),
	})
	response, err := server.Client().Post(server.URL+DefaultPath, MediaType, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST notification error = %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("response = %s body %x, want 204", response.Status, body)
	}
	if len(transport.calls) != 0 {
		t.Fatalf("relay calls = %#v, want local notification persistence during relay session", transport.calls)
	}
	notifications, err := store.ListNotifications(ctx, storage.DefaultTenantID, eidKey)
	if err != nil {
		t.Fatalf("ListNotifications() error = %v", err)
	}
	if len(notifications) != 1 || notifications[0].SequenceNumber != 24 || notifications[0].Kind != "install" {
		t.Fatalf("notifications = %#v, want install sequence 24", notifications)
	}
}

type esipaRecordingTransport struct {
	responses map[relay.Endpoint]relay.Response
	calls     []esipaTransportCall
}

type esipaTransportCall struct {
	address  string
	endpoint relay.Endpoint
	payload  []byte
}

func (t *esipaRecordingTransport) Post(_ context.Context, smdpAddress string, endpoint relay.Endpoint, payload []byte) (relay.Response, error) {
	t.calls = append(t.calls, esipaTransportCall{
		address:  smdpAddress,
		endpoint: endpoint,
		payload:  cloneBytes(payload),
	})
	return t.responses[endpoint], nil
}

func mustRelayHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return out
}
