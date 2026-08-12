package euiccpkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/pki"
)

// SGP.32 §2.11.1.2: euiccSignEPR covers euiccPackageResultDataSigned concatenated
// with associationToken (zero when unset). Hashing the data SEQUENCE alone fails.
func TestEuiccSignEPRRequiresAssociationTokenBinding(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	resultData, err := protocolasn1.IntegerEuiccResult(3, 0)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	data := protocolasn1.EuiccPackageResultDataSigned{
		EimID:            "eim.example",
		CounterValue:     15,
		EimTransactionID: []byte{0x16, 0xbd, 0x43, 0x80, 0x8e, 0xbb, 0x07, 0x56, 0x67, 0x52, 0x4b, 0x67, 0xbf, 0x61, 0xff, 0xcb},
		SeqNumber:        16,
		Results:          []protocolasn1.EuiccResultData{resultData},
	}
	signedDER := encode(t, &data)
	choiceWrapped := makeTLV([]byte{0xbf, 0x51}, makeTLV([]byte{0xa0}, append(cloneBytes(signedDER), makeTLV([]byte{0x5f, 0x37}, makeTR03111Sig(t, key, mustSignatureInput(t, signedDER, nil)))...)))

	raw, err := rawSignedDataFromResultDER(choiceWrapped)
	if err != nil {
		t.Fatalf("rawSignedDataFromResultDER() error = %v", err)
	}
	sig := choiceWrapped[len(choiceWrapped)-64:]

	if err := verifySignedBytes(&key.PublicKey, raw, sig); err == nil {
		t.Fatal("verify without associationToken unexpectedly succeeded")
	}
	signedInput := mustSignatureInput(t, raw, nil)
	if err := verifySignedBytes(&key.PublicKey, signedInput, sig); err != nil {
		t.Fatalf("verify with associationToken zero error = %v", err)
	}

	token := int64(7)
	iccid := []byte{0x89, 0x10}
	result, err := VerifyPackageResult(ResultInput{
		Request: &SignedRequest{
			EimID:            data.EimID,
			CounterValue:     data.CounterValue,
			EimTransactionID: cloneBytes(data.EimTransactionID),
			Package:          Enable(iccid, false),
		},
		ResultDER:        makeTLV([]byte{0xbf, 0x51}, makeTLV([]byte{0xa0}, append(cloneBytes(signedDER), makeTLV([]byte{0x5f, 0x37}, makeTR03111Sig(t, key, mustSignatureInput(t, signedDER, &token)))...))),
		EUICCPublicKey:   &key.PublicKey,
		AssociationToken: &token,
	})
	if err != nil {
		t.Fatalf("VerifyPackageResult(token=7) error = %v", err)
	}
	if !result.OK || result.Operation != OperationEnable {
		t.Fatalf("result = %#v, want successful enable", result)
	}
}

func mustSignatureInput(t *testing.T, signedDER []byte, token *int64) []byte {
	t.Helper()
	out, err := signatureInput(signedDER, token)
	if err != nil {
		t.Fatalf("signatureInput() error = %v", err)
	}
	return out
}

func makeTR03111Sig(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	sig, err := pki.SignECDSATR03111(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignECDSATR03111() error = %v", err)
	}
	return sig
}
