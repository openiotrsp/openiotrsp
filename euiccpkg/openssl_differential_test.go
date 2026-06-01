package euiccpkg

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestOpenSSLDifferentialASN1Parse(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatalf("openssl is required for the Stage 5 ASN.1 differential check: %v", err)
	}

	requestDER := opensslDifferentialRequestDER(t)
	assertOpenSSLASN1Tree(t, "EuiccPackageRequest", requestDER, []string{
		"cons: cont [ 81 ]",
		"cons:  SEQUENCE",
		"prim:   cont [ 0 ]",
		"prim:   appl [ 26 ]",
		"prim:   cont [ 1 ]",
		"cons:   cont [ 0 ]",
		"cons:    cont [ 3 ]",
		"prim:     appl [ 26 ]",
		"prim:  appl [ 55 ]",
	})

	resultDER := opensslDifferentialResultDER(t)
	assertOpenSSLASN1Tree(t, "EuiccPackageResult", resultDER, []string{
		"cons: cont [ 81 ]",
		"cons:  SEQUENCE",
		"cons:   SEQUENCE",
		"prim:    cont [ 0 ]",
		"prim:    cont [ 1 ]",
		"prim:    cont [ 3 ]",
		"cons:    SEQUENCE",
		"prim:     cont [ 3 ]",
		"prim:   appl [ 55 ]",
	})
}

func opensslDifferentialRequestDER(t *testing.T) []byte {
	t.Helper()
	store := memory.New()
	const eid = "eid-openssl-differential"
	if err := store.RegisterDevice(context.Background(), storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	service := &Service{
		Store:  store,
		Signer: fixedSigner{signature: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		EimID:  "testeim1",
	}
	request, err := service.Sign(context.Background(), SignInput{
		TenantID: storage.DefaultTenantID,
		EID:      eid,
		EIDValue: []byte{
			0x89, 0x01, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1,
		},
		Package: Enable([]byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1}, false),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return request.DER
}

func opensslDifferentialResultDER(t *testing.T) []byte {
	t.Helper()
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
	return encode(t, result)
}

func assertOpenSSLASN1Tree(t *testing.T, name string, der []byte, expected []string) {
	t.Helper()
	cmd := exec.Command("openssl", "asn1parse", "-inform", "DER", "-i")
	cmd.Stdin = bytes.NewReader(der)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse %s error = %v\n%s", name, err, output)
	}
	assertOrderedSubstrings(t, name, string(output), expected)
}

func assertOrderedSubstrings(t *testing.T, name string, output string, expected []string) {
	t.Helper()
	remaining := output
	for _, want := range expected {
		index := strings.Index(remaining, want)
		if index < 0 {
			t.Fatalf("openssl asn1parse %s missing %q after previous matches\nfull output:\n%s", name, want, output)
		}
		remaining = remaining[index+len(want):]
	}
}
