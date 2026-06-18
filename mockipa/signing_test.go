package mockipa

import (
	"context"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/esipa"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	"github.com/openiotrsp/openiotrsp/storage"
)

func TestSignedEUICCPackageResultVerifiesWithFixture(t *testing.T) {
	t.Parallel()

	fixture := requireSGP26SoftwareFixture(t)
	request := &protocolasn1.EuiccPackageRequest{
		EuiccPackageSigned: protocolasn1.EuiccPackageSigned{
			EimID:            "openiotrsp.eim",
			CounterValue:     1,
			EimTransactionID: []byte{0x01, 0x02},
			EuiccPackage: protocolasn1.EuiccPackage{
				Kind: protocolasn1.EuiccPackagePSMO,
				PSMOs: []protocolasn1.Psmo{{
					Operation: protocolasn1.PsmoEnable,
					ICCID:     []byte{0x89, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55},
				}},
			},
		},
	}
	result, operation, err := SignedEUICCPackageResult(fixture, nil, request, 0)
	if err != nil {
		t.Fatalf("SignedEUICCPackageResult() error = %v", err)
	}
	if operation != "enable" {
		t.Fatalf("operation = %q, want enable", operation)
	}
	resultDER, err := protocolasn1.Encode(result)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	resolver, err := esipa.NewStaticEUICCCertificateResolver(fixture.CICertificate, fixture.EUMCertificate, fixture.EUICCCertificate)
	if err != nil {
		t.Fatalf("NewStaticEUICCCertificateResolver() error = %v", err)
	}
	publicKey, err := resolver(context.Background(), storage.DefaultTenantID, fixture.EID)
	if err != nil {
		t.Fatalf("resolver() error = %v", err)
	}
	verified, err := euiccpkg.VerifyPackageResult(euiccpkg.ResultInput{
		Request: &euiccpkg.SignedRequest{
			EimID:            request.EuiccPackageSigned.EimID,
			CounterValue:     request.EuiccPackageSigned.CounterValue,
			EimTransactionID: request.EuiccPackageSigned.EimTransactionID,
			Package:          request.EuiccPackageSigned.EuiccPackage,
		},
		ResultDER:      resultDER,
		EUICCPublicKey: publicKey,
	})
	if err != nil {
		t.Fatalf("VerifyPackageResult() error = %v", err)
	}
	if !verified.OK {
		t.Fatalf("verified result = %#v, want OK", verified)
	}
}
