package mockipa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/openiotrsp/openiotrsp/esipa"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestCompactAuthenticateClientMatchesSoftwareEUICC(t *testing.T) {
	t.Parallel()

	fx := setupCompactDownload(t)
	ext := []byte{0x81, 0x01, 0x7f}
	compactBF38, signed, err := fx.euicc.CompactAuthenticateServerResponse(fx.signed1, fx.ctxParams1, ext, true)
	if err != nil {
		t.Fatalf("CompactAuthenticateServerResponse() error = %v", err)
	}
	request := mustTLV(t, bertlv.NewChildren(tagBF3B,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), fx.tx),
		compactBF38,
	))
	fx.transport.responses[relay.EndpointAuthenticateClient] = relay.Response{Payload: fx.authOK}
	fx.post(t, request, http.StatusOK)
	posted := fx.call(t, relay.EndpointAuthenticateClient)
	got := mustMarshal(t, parseTLV(t, posted).First(tagBF38).First(tagA0).First(tagSequence))
	if !bytes.Equal(got, mustMarshal(t, signed)) {
		t.Fatalf("euiccSigned1 = %x\nwant        %x", got, mustMarshal(t, signed))
	}
	if !bytes.Contains(posted, ext) {
		t.Fatal("relayed euiccSigned1 missing replaced extCardResource")
	}
}

func TestCompactPrepareDownloadMatchesSoftwareEUICC(t *testing.T) {
	t.Parallel()

	fx := setupCompactDownload(t)
	hashCC := bytes.Repeat([]byte{0xab}, 32)
	compactBF21, signed, err := fx.euicc.CompactPrepareDownloadResponse(fx.tx, hashCC)
	if err != nil {
		t.Fatalf("CompactPrepareDownloadResponse() error = %v", err)
	}
	request := mustTLV(t, bertlv.NewChildren(tagBF3A,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), fx.tx),
		compactBF21,
	))
	fx.transport.responses[relay.EndpointGetBoundProfilePackage] = relay.Response{Payload: fx.authOK}
	fx.post(t, request, http.StatusOK)
	posted := fx.call(t, relay.EndpointGetBoundProfilePackage)
	got := mustMarshal(t, parseTLV(t, posted).First(tagBF21).First(tagA0).First(tagSequence))
	if !bytes.Equal(got, mustMarshal(t, signed)) {
		t.Fatalf("euiccSigned2 = %x\nwant        %x", got, mustMarshal(t, signed))
	}
}

func TestCompactProfileInstallationResultMatchesSoftwareEUICC(t *testing.T) {
	t.Parallel()

	fx := setupCompactDownload(t)
	iccid := []byte{0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0xf6}
	aid := append([]byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10}, bytes.Repeat([]byte{0x00}, 7)...)
	aid = append(aid, 0x12, 0x34)
	metadata := mustTLV(t, bertlv.NewChildren(tagBF3B,
		bertlv.NewChildren(tagA0,
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), fx.tx),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(37),
				bertlv.NewValue(bertlv.Application.Primitive(26), iccid),
				bertlv.NewValue(bertlv.Application.Primitive(15), aid),
			),
		),
	))
	plain := mustTLV(t, bertlv.NewChildren(tagBF3B,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), fx.tx),
		bertlv.NewChildren(tagBF38,
			bertlv.NewChildren(tagA0,
				bertlv.NewChildren(tagSequence, bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), fx.tx)),
				bertlv.NewValue(bertlv.Application.Primitive(55), []byte{0x01}),
			),
		),
	))
	fx.transport.responses[relay.EndpointAuthenticateClient] = relay.Response{Payload: metadata}
	fx.post(t, plain, http.StatusOK)
	if posted := fx.call(t, relay.EndpointAuthenticateClient); !bytes.Equal(posted, plain) {
		t.Fatal("non-compact AuthenticateClient was rewritten")
	}

	compact, signed, err := fx.euicc.CompactProfileInstallationResult(fx.tx, fx.address, iccid, aid, 9)
	if err != nil {
		t.Fatalf("CompactProfileInstallationResult() error = %v", err)
	}
	request := mustTLV(t, bertlv.NewChildren(tagBF3D,
		bertlv.NewChildren(tagA0, compact),
	))
	fx.transport.responses[relay.EndpointHandleNotification] = relay.Response{NoContent: true}
	fx.post(t, request, http.StatusNoContent)
	posted := fx.call(t, relay.EndpointHandleNotification)
	got := mustMarshal(t, parseTLV(t, posted).First(tagBF37).First(bertlv.ContextSpecific.Constructed(39)))
	if !bytes.Equal(got, mustMarshal(t, signed)) {
		t.Fatalf("profileInstallationResultData = %x\nwant %x", got, mustMarshal(t, signed))
	}
}

var (
	tagSequence = bertlv.Universal.Constructed(16)
	tagA0       = bertlv.ContextSpecific.Constructed(0)
	tagBF20     = bertlv.ContextSpecific.Constructed(32)
	tagBF21     = bertlv.ContextSpecific.Constructed(33)
	tagBF37     = bertlv.ContextSpecific.Constructed(55)
	tagBF38     = bertlv.ContextSpecific.Constructed(56)
	tagBF39     = bertlv.ContextSpecific.Constructed(57)
	tagBF3A     = bertlv.ContextSpecific.Constructed(58)
	tagBF3B     = bertlv.ContextSpecific.Constructed(59)
	tagBF3D     = bertlv.ContextSpecific.Constructed(61)
)

type compactDownloadFixture struct {
	server     *httptest.Server
	transport  *compactRecordingTransport
	euicc      *SoftwareEUICC
	tx         []byte
	address    string
	signed1    *bertlv.TLV
	ctxParams1 *bertlv.TLV
	authOK     []byte
}

func (f compactDownloadFixture) post(t *testing.T, payload []byte, want int) {
	t.Helper()
	response, err := f.server.Client().Post(f.server.URL+esipa.DefaultPath, esipa.ASN1MediaType, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST error = %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("status = %s body %s, want %d", response.Status, body, want)
	}
}

func (f compactDownloadFixture) call(t *testing.T, endpoint relay.Endpoint) []byte {
	t.Helper()
	for i := len(f.transport.calls) - 1; i >= 0; i-- {
		if f.transport.calls[i].endpoint == endpoint {
			return f.transport.calls[i].payload
		}
	}
	t.Fatalf("no relay call for %s", endpoint)
	return nil
}

type compactRecordingTransport struct {
	responses map[relay.Endpoint]relay.Response
	calls     []compactTransportCall
}

type compactTransportCall struct {
	endpoint relay.Endpoint
	payload  []byte
}

func (t *compactRecordingTransport) Post(_ context.Context, _ string, endpoint relay.Endpoint, payload []byte) (relay.Response, error) {
	t.calls = append(t.calls, compactTransportCall{endpoint: endpoint, payload: append([]byte(nil), payload...)})
	return t.responses[endpoint], nil
}

func setupCompactDownload(t *testing.T) compactDownloadFixture {
	t.Helper()
	ctx := context.Background()
	euicc, certDER := newCompactSoftwareEUICC(t)
	store := memory.New()
	eidKey := hex.EncodeToString(bytes.Repeat([]byte{0x41}, 16))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	tx := bytes.Repeat([]byte{0x42}, 16)
	eimTx := bytes.Repeat([]byte{0x7e}, 16)
	const address = "smdp.example"
	trigger, err := profiledownload.NewActivationCodeTrigger("1$"+address+"$MATCHTOK", eimTx)
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}
	if _, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, eidKey, trigger); err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
	info2 := mustMarshal(t, euicc.EUICCInfo2())
	if err := store.SetEUICCState(ctx, storage.DefaultTenantID, storage.EUICCState{
		EID:              eidKey,
		EUICCInfo1:       mustMarshal(t, sampleCompactEUICCInfo1()),
		EUICCInfo2:       info2,
		IPACapabilities:  mustMarshal(t, sampleCompactCapabilities(0xf4)),
		DeviceInfo:       mustMarshal(t, sampleCompactDeviceInfo()),
		EUICCCertificate: wrapCompactCertificate(t, 6, certDER),
		EUMCertificate:   wrapCompactCertificate(t, 5, certDER),
	}); err != nil {
		t.Fatalf("SetEUICCState() error = %v", err)
	}
	signed1 := bertlv.NewChildren(tagSequence,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), tx),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), []byte(address)),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), bytes.Repeat([]byte{0x5a}, 16)),
	)
	initOK := mustTLV(t, bertlv.NewChildren(tagBF39,
		bertlv.NewChildren(tagA0,
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), tx),
			signed1,
			bertlv.NewValue(bertlv.Application.Primitive(55), []byte{0x11}),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xaa}),
			bertlv.NewChildren(tagSequence, bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xbb})),
		),
	))
	authOK := mustTLV(t, bertlv.NewChildren(tagBF3B,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), tx),
	))
	transport := &compactRecordingTransport{
		responses: map[relay.Endpoint]relay.Response{
			relay.EndpointInitiateAuthentication: {Payload: initOK},
		},
	}
	handler := esipa.NewHandler(store, storage.DefaultTenantID)
	handler.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	handler.Relay = relay.New(transport)
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)
	fx := compactDownloadFixture{
		server:    server,
		transport: transport,
		euicc:     euicc,
		tx:        tx,
		address:   address,
		signed1:   signed1,
		authOK:    authOK,
	}
	request := mustTLV(t, bertlv.NewChildren(tagBF39,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), bytes.Repeat([]byte{0xa5}, 16)),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), eimTx),
	))
	response, err := server.Client().Post(server.URL+esipa.DefaultPath, esipa.ASN1MediaType, bytes.NewReader(request))
	if err != nil {
		t.Fatalf("POST InitiateAuthentication error = %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("InitiateAuthentication status = %s body %s", response.Status, body)
	}
	root := parseTLV(t, body)
	field := root.First(tagA0).First(bertlv.ContextSpecific.Constructed(2))
	if field == nil || field.First(tagA0) == nil {
		t.Fatalf("InitiateAuthentication response missing ctxParams1: %x", body)
	}
	fx.ctxParams1 = field.First(tagA0)
	return fx
}

func sampleCompactEUICCInfo1() *bertlv.TLV {
	return bertlv.NewChildren(tagBF20,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x03, 0x02, 0x03, 0x00}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xaa, 0x01}),
		),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(10),
			bertlv.NewValue(bertlv.Universal.Primitive(4), []byte{0xbb, 0x02}),
		),
	)
}

func sampleCompactCapabilities(features byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(8),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x02, features}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte{0x07, 0x80}),
	)
}

func sampleCompactDeviceInfo() *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x35, 0x32, 0x30, 0x31}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1)),
	)
}

func wrapCompactCertificate(t *testing.T, tagNumber uint64, der []byte) []byte {
	t.Helper()
	return mustMarshal(t, bertlv.NewChildren(bertlv.ContextSpecific.Constructed(tagNumber), parseTLV(t, der)))
}

func newCompactSoftwareEUICC(t *testing.T) (*SoftwareEUICC, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "compact eUICC"},
		SubjectKeyId:          []byte{0xaa, 0xbb, 0xcc},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	euicc, err := NewSoftwareEUICC(&SGP26Fixture{
		CICertificate:    certDER,
		EUICCCertificate: certDER,
		EUMCertificate:   certDER,
		EUICCKey:         key,
	})
	if err != nil {
		t.Fatalf("NewSoftwareEUICC() error = %v", err)
	}
	return euicc, certDER
}

func parseTLV(t *testing.T, data []byte) *bertlv.TLV {
	t.Helper()
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	return tlv
}

func mustTLV(t *testing.T, tlv *bertlv.TLV) []byte {
	t.Helper()
	return mustMarshal(t, tlv)
}

func mustMarshal(t *testing.T, tlv *bertlv.TLV) []byte {
	t.Helper()
	if tlv == nil {
		t.Fatal("nil TLV")
	}
	raw, err := tlv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return raw
}
