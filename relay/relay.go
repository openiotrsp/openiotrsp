// Package relay forwards indirect profile-download ES9+ messages between the
// IPA and SM-DP+ without interpreting their signed payloads.
package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/driver"
	euichttp "github.com/damonto/euicc-go/http"
)

// Endpoint identifies the ES9+ HTTP endpoint reached through the relay.
type Endpoint string

const (
	EndpointInitiateAuthentication Endpoint = "/gsma/rsp2/es9plus/initiateAuthentication"
	EndpointAuthenticateClient     Endpoint = "/gsma/rsp2/es9plus/authenticateClient"
	EndpointGetBoundProfilePackage Endpoint = "/gsma/rsp2/es9plus/getBoundProfilePackage"
	EndpointHandleNotification     Endpoint = "/gsma/rsp2/es9plus/handleNotification"
	EndpointCancelSession          Endpoint = "/gsma/rsp2/es9plus/cancelSession"
)

const (
	defaultAdminProtocolVersion = "2.5.0"
	es9ASN1Path                 = "/gsma/rsp2/asn1"
	es9ASN1MediaType            = "application/x-gsma-rsp-asn1"
)

var (
	errMissingTransport   = errors.New("relay: missing transport")
	errMissingSMDPAddress = errors.New("relay: missing SM-DP+ address")
	errUnknownSession     = errors.New("relay: unknown SM-DP+ relay session")

	tagTransactionID             = bertlv.ContextSpecific.Primitive(0)
	tagSMDPAddress               = bertlv.ContextSpecific.Primitive(3)
	tagUTF8                      = bertlv.Universal.Primitive(12)
	tagRemoteProfileProvisioning = byte(0xa2)
)

// Response is the raw SM-DP+ response returned by a relay transport.
type Response struct {
	Payload   []byte
	NoContent bool
}

// Transport posts an already-formed ES9+ request to an SM-DP+ endpoint.
type Transport interface {
	Post(ctx context.Context, smdpAddress string, endpoint Endpoint, request []byte) (Response, error)
}

// Relay keeps only the routing state required to send all messages in a
// transaction to the same SM-DP+.
type Relay struct {
	Transport Transport

	mu            sync.Mutex
	byTransaction map[string]string
	defaultSMDP   string
}

// New creates a Relay using transport.
func New(transport Transport) *Relay {
	return &Relay{Transport: transport}
}

// Active reports whether the relay has an SM-DP+ route for an in-flight
// indirect-download session.
func (r *Relay) Active() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.defaultSMDP != "" || len(r.byTransaction) > 0
}

// InitiateAuthentication relays ES9+.InitiateAuthentication.
func (r *Relay) InitiateAuthentication(ctx context.Context, request []byte) (Response, error) {
	smdpAddress, err := smdpAddressFromInitiateAuthentication(request)
	if err != nil {
		return Response{}, err
	}
	response, err := r.post(ctx, smdpAddress, EndpointInitiateAuthentication, request)
	if err != nil {
		return Response{}, err
	}
	r.rememberSMDP(smdpAddress)
	r.rememberTransaction(transactionID(response.Payload), smdpAddress)
	return response, nil
}

// AuthenticateClient relays ES9+.AuthenticateClient.
func (r *Relay) AuthenticateClient(ctx context.Context, request []byte) (Response, error) {
	smdpAddress, err := r.smdpForTransaction(transactionID(request))
	if err != nil {
		return Response{}, err
	}
	response, err := r.post(ctx, smdpAddress, EndpointAuthenticateClient, request)
	if err != nil {
		return Response{}, err
	}
	r.rememberTransaction(transactionID(response.Payload), smdpAddress)
	return response, nil
}

// GetBoundProfilePackage relays ES9+.GetBoundProfilePackage.
func (r *Relay) GetBoundProfilePackage(ctx context.Context, request []byte) (Response, error) {
	smdpAddress, err := r.smdpForTransaction(transactionID(request))
	if err != nil {
		return Response{}, err
	}
	response, err := r.post(ctx, smdpAddress, EndpointGetBoundProfilePackage, request)
	if err != nil {
		return Response{}, err
	}
	r.rememberTransaction(transactionID(response.Payload), smdpAddress)
	return response, nil
}

// HandleNotification relays ES9+.HandleNotification. A 204 response from the
// SM-DP+ is surfaced as NoContent for the ESipa transport.
func (r *Relay) HandleNotification(ctx context.Context, request []byte) (Response, error) {
	smdpAddress := notificationAddress(request)
	if smdpAddress == "" {
		smdpAddress = r.defaultAddress()
	}
	if smdpAddress == "" {
		return Response{}, errMissingSMDPAddress
	}
	return r.post(ctx, smdpAddress, EndpointHandleNotification, request)
}

// CancelSession relays ES9+.CancelSession and forgets the transaction route on
// success.
func (r *Relay) CancelSession(ctx context.Context, request []byte) (Response, error) {
	txID := transactionID(request)
	smdpAddress, err := r.smdpForTransaction(txID)
	if err != nil {
		return Response{}, err
	}
	response, err := r.post(ctx, smdpAddress, EndpointCancelSession, request)
	if err != nil {
		return Response{}, err
	}
	r.forgetTransaction(txID)
	return response, nil
}

func (r *Relay) post(ctx context.Context, smdpAddress string, endpoint Endpoint, request []byte) (Response, error) {
	if r == nil || r.Transport == nil {
		return Response{}, errMissingTransport
	}
	if strings.TrimSpace(smdpAddress) == "" {
		return Response{}, errMissingSMDPAddress
	}
	return r.Transport.Post(ctx, smdpAddress, endpoint, cloneBytes(request))
}

func (r *Relay) rememberSMDP(smdpAddress string) {
	if r == nil || smdpAddress == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultSMDP = smdpAddress
}

func (r *Relay) rememberTransaction(transactionID []byte, smdpAddress string) {
	if r == nil || len(transactionID) == 0 || smdpAddress == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byTransaction == nil {
		r.byTransaction = make(map[string]string)
	}
	r.byTransaction[hex.EncodeToString(transactionID)] = smdpAddress
}

func (r *Relay) forgetTransaction(transactionID []byte) {
	if r == nil || len(transactionID) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byTransaction, hex.EncodeToString(transactionID))
}

func (r *Relay) smdpForTransaction(transactionID []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(transactionID) > 0 && r.byTransaction != nil {
		if smdpAddress := r.byTransaction[hex.EncodeToString(transactionID)]; smdpAddress != "" {
			return smdpAddress, nil
		}
	}
	if r.defaultSMDP != "" {
		return r.defaultSMDP, nil
	}
	return "", errUnknownSession
}

func (r *Relay) defaultAddress() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.defaultSMDP
}

// HTTPTransport posts raw relay payloads using the SGP.22 ES9+ ASN.1 HTTP
// binding and euicc-go's HTTP client configuration so the SGP.26 CI root bundle
// is trusted.
type HTTPTransport struct {
	HTTPClient           *http.Client
	AdminProtocolVersion string
}

// Post sends a raw ES9+ function message to smdpAddress using the ASN.1
// RemoteProfileProvisioningRequest wrapper required by SGP.22.
func (t HTTPTransport) Post(ctx context.Context, smdpAddress string, _ Endpoint, payload []byte) (Response, error) {
	target, err := endpointURL(smdpAddress)
	if err != nil {
		return Response{}, err
	}
	requestPayload, err := wrapRemoteProfileProvisioning(payload)
	if err != nil {
		return Response{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(requestPayload))
	if err != nil {
		return Response{}, err
	}
	request.Header = t.header()
	client := t.HTTPClient
	if client == nil {
		client = driver.NewHTTPClient(slog.Default(), 60*time.Second)
	}
	httpResponse, err := client.Do(request)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = httpResponse.Body.Close()
	}()
	if httpResponse.StatusCode == http.StatusNoContent {
		return Response{NoContent: true}, nil
	}
	body, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return Response{}, err
	}
	if httpResponse.StatusCode > 299 {
		return Response{}, fmt.Errorf("relay: SM-DP+ returned %s: %s", httpResponse.Status, strings.TrimSpace(string(body)))
	}
	responsePayload, err := unwrapRemoteProfileProvisioning(body)
	if err != nil {
		return Response{}, err
	}
	return Response{Payload: responsePayload}, nil
}

func (t HTTPTransport) header() http.Header {
	version := strings.TrimSpace(t.AdminProtocolVersion)
	if version == "" {
		version = defaultAdminProtocolVersion
	}
	header := (&euichttp.Client{AdminProtocolVersion: version}).Header()
	header.Set("Content-Type", es9ASN1MediaType)
	return header
}

func endpointURL(smdpAddress string) (*url.URL, error) {
	raw := strings.TrimSpace(smdpAddress)
	if raw == "" {
		return nil, errMissingSMDPAddress
	}
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		raw = "https://" + raw
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if base.Host == "" {
		return nil, fmt.Errorf("relay: invalid SM-DP+ address %q", smdpAddress)
	}
	return base.JoinPath(strings.TrimPrefix(es9ASN1Path, "/")), nil
}

func wrapRemoteProfileProvisioning(payload []byte) ([]byte, error) {
	if _, _, err := tlvContent(payload); err != nil {
		return nil, err
	}
	out := []byte{tagRemoteProfileProvisioning}
	out = append(out, encodeDERLength(len(payload))...)
	out = append(out, cloneBytes(payload)...)
	return out, nil
}

func unwrapRemoteProfileProvisioning(payload []byte) ([]byte, error) {
	tag, content, err := tlvContent(payload)
	if err != nil {
		return nil, err
	}
	if len(tag) != 1 || tag[0] != tagRemoteProfileProvisioning {
		return nil, fmt.Errorf("relay: SM-DP+ response has tag %x, want a2", tag)
	}
	if _, _, err := tlvContent(content); err != nil {
		return nil, fmt.Errorf("relay: invalid RemoteProfileProvisioningResponse child: %w", err)
	}
	return cloneBytes(content), nil
}

func tlvContent(data []byte) ([]byte, []byte, error) {
	tag, length, headerLen, err := tlvHeader(data)
	if err != nil {
		return nil, nil, err
	}
	if len(data)-headerLen != length {
		return nil, nil, errors.New("relay: trailing or truncated BER-TLV payload")
	}
	return tag, data[headerLen:], nil
}

func tlvHeader(data []byte) ([]byte, int, int, error) {
	if len(data) == 0 {
		return nil, 0, 0, errors.New("relay: empty BER-TLV payload")
	}
	index := 1
	if data[0]&0x1f == 0x1f {
		for {
			if index >= len(data) {
				return nil, 0, 0, errors.New("relay: truncated BER-TLV tag")
			}
			b := data[index]
			index++
			if b&0x80 == 0 {
				break
			}
		}
	}
	if index >= len(data) {
		return nil, 0, 0, errors.New("relay: missing BER-TLV length")
	}
	lengthByte := data[index]
	index++
	if lengthByte&0x80 == 0 {
		return cloneBytes(data[:index-1]), int(lengthByte), index, nil
	}
	lengthOctets := int(lengthByte & 0x7f)
	if lengthOctets == 0 {
		return nil, 0, 0, errors.New("relay: indefinite BER-TLV length is not supported")
	}
	if lengthOctets > len(data)-index {
		return nil, 0, 0, errors.New("relay: truncated BER-TLV length")
	}
	length := 0
	for _, b := range data[index : index+lengthOctets] {
		length = length<<8 | int(b)
	}
	index += lengthOctets
	return cloneBytes(data[:index-lengthOctets-1]), length, index, nil
}

func encodeDERLength(length int) []byte {
	if length < 0 {
		panic("negative length")
	}
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var reversed [8]byte
	count := 0
	for value := length; value > 0; value >>= 8 {
		reversed[count] = byte(value)
		count++
	}
	out := make([]byte, 1+count)
	out[0] = 0x80 | byte(count)
	for index := range count {
		out[1+index] = reversed[count-1-index]
	}
	return out
}

func smdpAddressFromInitiateAuthentication(data []byte) (string, error) {
	tlv, err := parseTLV(data)
	if err != nil {
		return "", err
	}
	child := firstTLV(tlv, tagSMDPAddress)
	if child == nil || len(child.Value) == 0 {
		return "", errMissingSMDPAddress
	}
	return string(child.Value), nil
}

func transactionID(data []byte) []byte {
	tlv, err := parseTLV(data)
	if err != nil {
		return nil
	}
	if child := firstTLV(tlv, tagTransactionID); child != nil {
		return cloneBytes(child.Value)
	}
	return nil
}

func notificationAddress(data []byte) string {
	tlv, err := parseTLV(data)
	if err != nil {
		return ""
	}
	if child := firstTLV(tlv, tagUTF8); child != nil {
		return string(child.Value)
	}
	return ""
}

func parseTLV(data []byte) (*bertlv.TLV, error) {
	if len(data) == 0 {
		return nil, errors.New("relay: empty BER-TLV payload")
	}
	reader := bytes.NewReader(data)
	tlv := new(bertlv.TLV)
	n, err := tlv.ReadFrom(reader)
	if err != nil {
		return nil, err
	}
	if n != int64(len(data)) || reader.Len() != 0 {
		return nil, errors.New("relay: trailing data after BER-TLV payload")
	}
	return tlv, nil
}

func firstTLV(tlv *bertlv.TLV, tag bertlv.Tag) *bertlv.TLV {
	if tlv == nil {
		return nil
	}
	if tlv.Tag.Equal(tag) {
		return tlv
	}
	for _, child := range tlv.Children {
		if found := firstTLV(child, tag); found != nil {
			return found
		}
	}
	return nil
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
