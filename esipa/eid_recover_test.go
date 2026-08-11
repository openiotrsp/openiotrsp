package esipa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/ipadata"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestRecoverEIDFromIpaEuiccDataCertificate(t *testing.T) {
	t.Parallel()

	eid := testEID(0x21)
	certDER := selfSignedEUICCCertWithEID(t, hex.EncodeToString(eid))
	bf52 := constructed(tagIpaEuiccData,
		constructed(bertlv.ContextSpecific.Constructed(6), mustParseCertTLV(t, certDER)),
	)

	got := recoverEIDFromPackageResultTLV(bf52)
	if !bytes.Equal(got, eid) {
		t.Fatalf("recovered EID = %x, want %x", got, eid)
	}
}

func TestRecoverEIDFromIpaEuiccDataPrefersEmbeddedEID(t *testing.T) {
	t.Parallel()

	embedded := testEID(0x22)
	certEID := testEID(0x23)
	certDER := selfSignedEUICCCertWithEID(t, hex.EncodeToString(certEID))
	bf52 := constructed(tagIpaEuiccData,
		octetTLV(tagEID, embedded),
		constructed(bertlv.ContextSpecific.Constructed(6), mustParseCertTLV(t, certDER)),
	)

	got := recoverEIDFromPackageResultTLV(bf52)
	if !bytes.Equal(got, embedded) {
		t.Fatalf("recovered EID = %x, want embedded %x", got, embedded)
	}
}

func TestProvideTLVFromGSMARecoversEIDFromBF52Certificate(t *testing.T) {
	t.Parallel()

	eid := testEID(0x24)
	certDER := selfSignedEUICCCertWithEID(t, hex.EncodeToString(eid))
	bf52 := constructed(tagIpaEuiccData,
		constructed(bertlv.ContextSpecific.Constructed(6), mustParseCertTLV(t, certDER)),
		octetTLV(bertlv.ContextSpecific.Primitive(7), []byte{0x01, 0x02}),
	)
	resultDER, err := bf52.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	provideTLV, err := provideTLVFromGSMA("", base64.StdEncoding.EncodeToString(resultDER))
	if err != nil {
		t.Fatalf("provideTLVFromGSMA() error = %v", err)
	}
	if !provideTLV.Tag.Equal(tagProvideResult) {
		t.Fatalf("tag = %s, want BF50", provideTLV.Tag)
	}
	eidChild := provideTLV.First(tagEID)
	if eidChild == nil || !bytes.Equal(eidChild.Value, eid) {
		t.Fatalf("provide EID = %#v, want %x", eidChild, eid)
	}
}

func TestGSMAJSONProvideBF52RecoversEIDFromCertificate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := testEID(0x25)
	eidKey := hex.EncodeToString(eid)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	transactionID := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	if _, err := ipadata.EnqueueRequest(ctx, store, storage.DefaultTenantID, eidKey, ipadata.RequestInput{
		TagList:          []byte{0xa6},
		EimTransactionID: transactionID,
	}); err != nil {
		t.Fatalf("EnqueueRequest() error = %v", err)
	}

	handler := NewHandler(store, storage.DefaultTenantID)
	server := httptest.NewServer(handler.HTTPHandler())
	t.Cleanup(server.Close)

	certDER := selfSignedEUICCCertWithEID(t, eidKey)
	response := &protocolasn1.IpaEuiccDataResponse{
		Data: &protocolasn1.IpaEuiccData{
			RawObjects: []*bertlv.TLV{
				constructed(bertlv.ContextSpecific.Constructed(6), mustParseCertTLV(t, certDER)),
				octetTLV(bertlv.ContextSpecific.Primitive(7), transactionID),
			},
		},
	}
	resultDER := encode(t, response)
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 200 or 204", resp.StatusCode)
	}
	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %#v, want empty after BF52 EID recovery", pending)
	}
}

func selfSignedEUICCCertWithEID(t *testing.T, eidHex string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{SerialNumber: eidHex},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return der
}

func mustParseCertTLV(t *testing.T, der []byte) *bertlv.TLV {
	t.Helper()
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(der); err != nil {
		t.Fatalf("parse certificate TLV: %v", err)
	}
	return tlv
}
