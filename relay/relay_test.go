package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRelayRoutesSequenceByTransactionWithoutChangingPayloads(t *testing.T) {
	t.Parallel()

	initRequest := mustHex(t, "bf398110830b6578616d706c652e636f6d8101ff")
	initResponse := mustHex(t, "bf39058003010203")
	authRequest := mustHex(t, "bf3b058003010203")
	authResponse := mustHex(t, "bf3b058003010203")
	getRequest := mustHex(t, "bf3a058003010203")
	getResponse := mustHex(t, "bf3a058003010203")
	notificationRequest := mustHex(t, "bf3d0d0c0b6578616d706c652e636f6d")
	cancelRequest := mustHex(t, "bf41058003010203")
	cancelResponse := mustHex(t, "bf4100")

	transport := &recordingTransport{
		responses: map[Endpoint]Response{
			EndpointInitiateAuthentication: {Payload: initResponse},
			EndpointAuthenticateClient:     {Payload: authResponse},
			EndpointGetBoundProfilePackage: {Payload: getResponse},
			EndpointHandleNotification:     {NoContent: true},
			EndpointCancelSession:          {Payload: cancelResponse},
		},
	}
	relay := New(transport)
	ctx := context.Background()

	if got, err := relay.InitiateAuthentication(ctx, initRequest); err != nil {
		t.Fatalf("InitiateAuthentication() error = %v", err)
	} else if !bytes.Equal(got.Payload, initResponse) {
		t.Fatalf("init response = %x, want %x", got.Payload, initResponse)
	}
	if got, err := relay.AuthenticateClient(ctx, authRequest); err != nil {
		t.Fatalf("AuthenticateClient() error = %v", err)
	} else if !bytes.Equal(got.Payload, authResponse) {
		t.Fatalf("auth response = %x, want %x", got.Payload, authResponse)
	}
	if got, err := relay.GetBoundProfilePackage(ctx, getRequest); err != nil {
		t.Fatalf("GetBoundProfilePackage() error = %v", err)
	} else if !bytes.Equal(got.Payload, getResponse) {
		t.Fatalf("bound package response = %x, want %x", got.Payload, getResponse)
	}
	if got, err := relay.HandleNotification(ctx, notificationRequest); err != nil {
		t.Fatalf("HandleNotification() error = %v", err)
	} else if !got.NoContent {
		t.Fatalf("HandleNotification() = %#v, want no content", got)
	}
	if got, err := relay.CancelSession(ctx, cancelRequest); err != nil {
		t.Fatalf("CancelSession() error = %v", err)
	} else if !bytes.Equal(got.Payload, cancelResponse) {
		t.Fatalf("cancel response = %x, want %x", got.Payload, cancelResponse)
	}

	want := []transportCall{
		{address: "example.com", endpoint: EndpointInitiateAuthentication, payload: initRequest},
		{address: "example.com", endpoint: EndpointAuthenticateClient, payload: authRequest},
		{address: "example.com", endpoint: EndpointGetBoundProfilePackage, payload: getRequest},
		{address: "example.com", endpoint: EndpointHandleNotification, payload: notificationRequest},
		{address: "example.com", endpoint: EndpointCancelSession, payload: cancelRequest},
	}
	if len(transport.calls) != len(want) {
		t.Fatalf("transport calls = %d, want %d", len(transport.calls), len(want))
	}
	for index := range want {
		got := transport.calls[index]
		if got.address != want[index].address || got.endpoint != want[index].endpoint || !bytes.Equal(got.payload, want[index].payload) {
			t.Fatalf("call %d = %#v payload %x, want %#v payload %x", index, got, got.payload, want[index], want[index].payload)
		}
	}
}

func TestHTTPTransportUsesASN1BindingAndPreservesPayload(t *testing.T) {
	t.Parallel()

	initRequest := mustHex(t, "bf398110830b6578616d706c652e636f6d8101ff")
	initResponse := mustHex(t, "bf3981058003010203")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != es9ASN1Path {
			t.Fatalf("request path = %q, want %q", r.URL.Path, es9ASN1Path)
		}
		if got := r.Header.Get("Content-Type"); got != es9ASN1MediaType {
			t.Fatalf("Content-Type = %q, want %q", got, es9ASN1MediaType)
		}
		if got := r.Header.Get("X-Admin-Protocol"); got != "gsma/rsp/v2.5.0" {
			t.Fatalf("X-Admin-Protocol = %q, want gsma/rsp/v2.5.0", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll(request) error = %v", err)
		}
		wantBody, err := wrapRemoteProfileProvisioning(initRequest)
		if err != nil {
			t.Fatalf("wrapRemoteProfileProvisioning(request) error = %v", err)
		}
		if !bytes.Equal(body, wantBody) {
			t.Fatalf("request body = %x, want %x", body, wantBody)
		}
		responseBody, err := wrapRemoteProfileProvisioning(initResponse)
		if err != nil {
			t.Fatalf("wrapRemoteProfileProvisioning(response) error = %v", err)
		}
		w.Header().Set("Content-Type", es9ASN1MediaType)
		_, _ = w.Write(responseBody)
	}))
	t.Cleanup(server.Close)

	response, err := (HTTPTransport{HTTPClient: server.Client()}).Post(context.Background(), server.URL, EndpointInitiateAuthentication, initRequest)
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if !bytes.Equal(response.Payload, initResponse) {
		t.Fatalf("response payload = %x, want %x", response.Payload, initResponse)
	}
}

func TestRelayRoutesConcurrentTransactionsWithoutDefaultFallback(t *testing.T) {
	t.Parallel()

	initA := mustHex(t, "bf390e8309612e6578616d706c658101ff")
	initB := mustHex(t, "bf390e8309622e6578616d706c658101ff")
	initResponseA := mustHex(t, "bf39058003aa0001")
	initResponseB := mustHex(t, "bf39058003bb0002")
	authA := mustHex(t, "bf3b058003aa0001")
	authB := mustHex(t, "bf3b058003bb0002")
	authResponseA := mustHex(t, "bf3b058003aa0001")
	authResponseB := mustHex(t, "bf3b058003bb0002")
	notificationA := mustHex(t, "bf3d058003aa0001")

	transport := &recordingTransport{
		responsesByPayload: map[string]Response{
			hex.EncodeToString(initA):         {Payload: initResponseA},
			hex.EncodeToString(initB):         {Payload: initResponseB},
			hex.EncodeToString(authA):         {Payload: authResponseA},
			hex.EncodeToString(authB):         {Payload: authResponseB},
			hex.EncodeToString(notificationA): {NoContent: true},
		},
	}
	relay := New(transport)
	ctx := context.Background()

	if _, err := relay.InitiateAuthentication(ctx, initA); err != nil {
		t.Fatalf("InitiateAuthentication(A) error = %v", err)
	}
	if _, err := relay.InitiateAuthentication(ctx, initB); err != nil {
		t.Fatalf("InitiateAuthentication(B) error = %v", err)
	}
	if _, err := relay.AuthenticateClient(ctx, authA); err != nil {
		t.Fatalf("AuthenticateClient(A) error = %v", err)
	}
	if _, err := relay.AuthenticateClient(ctx, authB); err != nil {
		t.Fatalf("AuthenticateClient(B) error = %v", err)
	}
	if got, err := relay.HandleNotification(ctx, notificationA); err != nil {
		t.Fatalf("HandleNotification(A) error = %v", err)
	} else if !got.NoContent {
		t.Fatalf("HandleNotification(A) = %#v, want no content", got)
	}

	want := []transportCall{
		{address: "a.example", endpoint: EndpointInitiateAuthentication, payload: initA},
		{address: "b.example", endpoint: EndpointInitiateAuthentication, payload: initB},
		{address: "a.example", endpoint: EndpointAuthenticateClient, payload: authA},
		{address: "b.example", endpoint: EndpointAuthenticateClient, payload: authB},
		{address: "a.example", endpoint: EndpointHandleNotification, payload: notificationA},
	}
	assertTransportCalls(t, transport.calls, want)
}

func TestRelayRejectsUnknownTransactionInsteadOfUsingLatestSMDP(t *testing.T) {
	t.Parallel()

	initRequest := mustHex(t, "bf398110830b6578616d706c652e636f6d8101ff")
	initResponse := mustHex(t, "bf39058003010203")
	unknownAuth := mustHex(t, "bf3b058003040506")
	transport := &recordingTransport{
		responses: map[Endpoint]Response{
			EndpointInitiateAuthentication: {Payload: initResponse},
		},
	}
	relay := New(transport)
	if _, err := relay.InitiateAuthentication(context.Background(), initRequest); err != nil {
		t.Fatalf("InitiateAuthentication() error = %v", err)
	}
	if _, err := relay.AuthenticateClient(context.Background(), unknownAuth); !errors.Is(err, errUnknownSession) {
		t.Fatalf("AuthenticateClient(unknown) error = %v, want %v", err, errUnknownSession)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("transport calls = %#v, want only initiateAuthentication", transport.calls)
	}
}

type recordingTransport struct {
	responses          map[Endpoint]Response
	responsesByPayload map[string]Response
	calls              []transportCall
}

type transportCall struct {
	address  string
	endpoint Endpoint
	payload  []byte
}

func (t *recordingTransport) Post(_ context.Context, smdpAddress string, endpoint Endpoint, payload []byte) (Response, error) {
	t.calls = append(t.calls, transportCall{
		address:  smdpAddress,
		endpoint: endpoint,
		payload:  cloneBytes(payload),
	})
	if response, ok := t.responsesByPayload[hex.EncodeToString(payload)]; ok {
		return response, nil
	}
	return t.responses[endpoint], nil
}

func assertTransportCalls(t *testing.T, got []transportCall, want []transportCall) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("transport calls = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index].address != want[index].address || got[index].endpoint != want[index].endpoint || !bytes.Equal(got[index].payload, want[index].payload) {
			t.Fatalf("call %d = %#v payload %x, want %#v payload %x", index, got[index], got[index].payload, want[index], want[index].payload)
		}
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return out
}
