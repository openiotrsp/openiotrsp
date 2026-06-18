package mockipa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

// SignedEUICCPackageResult builds a verifiable SGP.32 EuiccPackageResult using the
// SGP.26 test eUICC signing key. SGP.32 package results use DER ECDSA signatures.
func SignedEUICCPackageResult(fixture *SGP26Fixture, device *DeviceState, request *protocolasn1.EuiccPackageRequest, sequenceNumber int64) (*protocolasn1.EuiccPackageResult, string, error) {
	if fixture == nil || fixture.EUICCKey == nil {
		return nil, "", fmt.Errorf("mockipa: missing SGP.26 eUICC signing key")
	}
	if request == nil {
		return nil, "", fmt.Errorf("mockipa: missing eUICC package request")
	}
	pkg := request.EuiccPackageSigned.EuiccPackage
	resultData, operation, err := successfulResultData(pkg, request.EuiccPackageSigned.EimID, device)
	if err != nil {
		return nil, "", err
	}
	signed := protocolasn1.EuiccPackageResultDataSigned{
		EimID:            request.EuiccPackageSigned.EimID,
		CounterValue:     request.EuiccPackageSigned.CounterValue,
		EimTransactionID: cloneBytes(request.EuiccPackageSigned.EimTransactionID),
		SeqNumber:        sequenceNumber,
		Results:          []protocolasn1.EuiccResultData{resultData},
	}
	signature, err := signSGP32Marshaler(fixture.EUICCKey, &signed)
	if err != nil {
		return nil, "", err
	}
	return &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultOK,
		Signed: &protocolasn1.EuiccPackageResultSigned{
			Data:         signed,
			EuiccSignEPR: signature,
		},
	}, operation, nil
}

func signSGP32Marshaler(key *ecdsa.PrivateKey, value protocolasn1.Marshaler) ([]byte, error) {
	tlv, err := value.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	payload, err := tlv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}
