package euiccpkg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

// TestKnownAnswerDERFromSGP33SymbolicFixtures pins the eUICC package bytes for
// the SGP.33-1 v1.2 section 4.2.31 / Annex C symbolic enable fixture. SGP.33-1
// gives ASN.1 structures and symbolic parameters, not a published raw DER hex
// vector, so the substituted fixture values are fixed here and the resulting DER
// is hardcoded rather than round-tripped from dynamic test data.
func TestKnownAnswerDERFromSGP33SymbolicFixtures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	const eid = "eid-known-answer"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	service := &Service{
		Store:  store,
		Signer: fixedSigner{signature: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		EimID:  "testeim1",
	}
	request, err := service.Sign(ctx, SignInput{
		TenantID: storage.DefaultTenantID,
		EID:      eid,
		EIDValue: []byte{
			0x89, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
		Package: Enable([]byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1}, false),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	assertKnownAnswerHex(t, request.DER, "bf5139302f80087465737465696d315a1089010000000000000000000000000001810101a00ea30c5a0a891010123456789012f15f37053003020101")

	resultData, err := protocolasn1.IntegerEuiccResult(3, 0)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	result := &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultOK,
		Signed: &protocolasn1.EuiccPackageResultSigned{
			Data: protocolasn1.EuiccPackageResultDataSigned{
				EimID:        "testeim1",
				CounterValue: 1,
				SeqNumber:    1,
				Results:      []protocolasn1.EuiccResultData{resultData},
			},
			EuiccSignEPR: []byte{0x30, 0x03, 0x02, 0x01, 0x02},
		},
	}
	assertKnownAnswerHex(t, encode(t, result), "bf5121301f301580087465737465696d3181010183010130038301005f37053003020102")
}

type fixedSigner struct {
	signature []byte
}

func (s fixedSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloneBytes(s.signature), nil
}

func (s fixedSigner) PublicKey() crypto.PublicKey {
	return nil
}

func (s fixedSigner) CertificateDER() []byte {
	return nil
}

func assertKnownAnswerHex(t *testing.T, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("bad known-answer hex %q: %v", wantHex, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("known-answer DER mismatch\n got %x\nwant %x", got, want)
	}
}
