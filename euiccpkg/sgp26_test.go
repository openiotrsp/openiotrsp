package euiccpkg

import (
	"archive/zip"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/pki"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

const sgp26ZipPath = "../spec/SGP.26_v3.0.2-17-July-2025.zip"

var sgp26VariantONISTFiles = map[string]string{
	"ci":       "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/CI/CERT_CI_SIG_NIST.der",
	"euicc":    "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/CERT_EUICC_SIG_NIST.der",
	"eum":      "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/EUM/CERT_EUM_SIG_NIST.der",
	"euiccKey": "SGP.26_v3.0.2-20240828_Files_draft3_2025/Valid Test Cases/Variant O/eUICC/SK_EUICC_SIG_NIST.pem",
}

func TestSGP26SignedEuiccPackageResult(t *testing.T) {
	t.Parallel()

	sgp26 := loadSGP26VariantONISTFiles(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	validator, err := pki.NewValidator([][]byte{sgp26["ci"]}, pki.WithCurrentTime(now))
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	if err := validator.ValidateEUICCChain([][]byte{sgp26["euicc"], sgp26["eum"]}); err != nil {
		t.Fatalf("ValidateEUICCChain() error = %v", err)
	}

	euiccPrivateKey := parseSGP26ECDSAPrivateKey(t, sgp26["euiccKey"])
	euiccCert := parseSGP26Certificate(t, sgp26["euicc"])
	euiccPublicKey, ok := euiccCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("eUICC certificate public key type = %T, want *ecdsa.PublicKey", euiccCert.PublicKey)
	}
	if !euiccPrivateKey.PublicKey.Equal(euiccPublicKey) {
		t.Fatalf("SGP.26 eUICC private key does not match eUICC certificate public key")
	}

	ctx := context.Background()
	store := memory.New()
	eid := "eid-sgp26-signed-result"
	eidValue := []byte{0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	iccid := []byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1}
	registerWithState(t, store, eid, storage.ProfileState{
		EID:       eid,
		ICCID:     hex.EncodeToString(iccid),
		IsEnabled: false,
	})

	service := &Service{Store: store, Signer: newTestSigner(t), EimID: "testeim1"}
	request := signPackage(t, ctx, service, eid, eidValue, []byte{0xaa, 0x55}, Enable(iccid, false))
	operation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationEuiccPackage,
		Payload: request.DER,
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	resultDER := sgp26SignedResultDER(t, euiccPrivateKey, request, operation.SequenceNumber, 3, 0)
	result, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        request,
		ResultDER:      resultDER,
		EUICCPublicKey: euiccPublicKey,
		OperationID:    operation.ID,
		SequenceNumber: operation.SequenceNumber,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult() error = %v", err)
	}
	if !result.OK || result.Operation != OperationEnable || result.ResultCode != ResultOK {
		t.Fatalf("result = %#v, want successful enable", result)
	}
	assertProfileEnabled(t, store, eid, iccid, boolPtr(true))
}

func sgp26SignedResultDER(
	t *testing.T,
	key *ecdsa.PrivateKey,
	request *SignedRequest,
	sequenceNumber int64,
	resultTag uint64,
	resultCode int64,
) []byte {
	t.Helper()
	resultData, err := protocolasn1.IntegerEuiccResult(resultTag, resultCode)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	data := protocolasn1.EuiccPackageResultDataSigned{
		EimID:            request.EimID,
		CounterValue:     request.CounterValue,
		EimTransactionID: cloneBytes(request.EimTransactionID),
		SeqNumber:        sequenceNumber,
		Results:          []protocolasn1.EuiccResultData{resultData},
	}
	signature := signSGP26Marshaler(t, key, &data)
	return encode(t, &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultOK,
		Signed: &protocolasn1.EuiccPackageResultSigned{
			Data:         data,
			EuiccSignEPR: signature,
		},
	})
}

func signSGP26Marshaler(t *testing.T, key *ecdsa.PrivateKey, value protocolasn1.Marshaler) []byte {
	t.Helper()
	payload := encode(t, value)
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}
	return signature
}

func loadSGP26VariantONISTFiles(t *testing.T) map[string][]byte {
	t.Helper()
	if _, err := os.Stat(sgp26ZipPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("SGP.26 ZIP not present at %s", sgp26ZipPath)
		}
		t.Fatalf("stat SGP.26 ZIP: %v", err)
	}

	reader, err := zip.OpenReader(sgp26ZipPath)
	if err != nil {
		t.Fatalf("open SGP.26 ZIP: %v", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Fatalf("close SGP.26 ZIP: %v", err)
		}
	}()

	entries := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		entries[file.Name] = file
	}
	out := make(map[string][]byte, len(sgp26VariantONISTFiles))
	for name, path := range sgp26VariantONISTFiles {
		file := entries[path]
		if file == nil {
			t.Fatalf("SGP.26 ZIP missing %s", path)
		}
		out[name] = readSGP26ZipFile(t, file)
	}
	return out
}

func readSGP26ZipFile(t *testing.T, file *zip.File) []byte {
	t.Helper()
	reader, err := file.Open()
	if err != nil {
		t.Fatalf("open %s in ZIP: %v", file.Name, err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Fatalf("close %s in ZIP: %v", file.Name, err)
		}
	}()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read %s in ZIP: %v", file.Name, err)
	}
	return data
}

func parseSGP26ECDSAPrivateKey(t *testing.T, pemBytes []byte) *ecdsa.PrivateKey {
	t.Helper()
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		pemBytes = rest
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if ok {
			return ecdsaKey
		}
	}
	t.Fatalf("parse SGP.26 eUICC private key: no ECDSA private key PEM block found")
	return nil
}

func parseSGP26Certificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse SGP.26 certificate: %v", err)
	}
	return cert
}
