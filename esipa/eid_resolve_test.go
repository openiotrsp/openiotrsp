package esipa

import (
	"bytes"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
)

func TestEimTransactionIDFromResultTLVProfileDownloadTrigger(t *testing.T) {
	t.Parallel()

	transactionID := []byte{0x01, 0x02}
	resultTLV := mustTLV(t, &protocolasn1.ProfileDownloadTriggerResult{
		EimTransactionID: transactionID,
		ProfileInstallationRaw: profileInstallationResultTLV(
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0)),
		),
	})

	got := EimTransactionIDFromResultTLV(resultTLV)
	if !bytes.Equal(got, transactionID) {
		t.Fatalf("EimTransactionIDFromResultTLV() = %x, want %x", got, transactionID)
	}
}

func TestEimTransactionIDFromResultTLVEimPackageResultProfileDownload(t *testing.T) {
	t.Parallel()

	transactionID := []byte{0x03, 0x04}
	profileResult := &protocolasn1.ProfileDownloadTriggerResult{
		EimTransactionID: transactionID,
		ProfileInstallationRaw: profileInstallationResultTLV(
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0)),
		),
	}
	eimResult := protocolasn1.EimPackageResult{
		Kind:                  protocolasn1.EimPackageResultProfileDownload,
		ProfileDownloadResult: profileResult,
	}
	resultTLV, err := eimResult.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}

	got := EimTransactionIDFromResultTLV(resultTLV)
	if !bytes.Equal(got, transactionID) {
		t.Fatalf("EimTransactionIDFromResultTLV() = %x, want %x", got, transactionID)
	}
}

func TestOperationMatchesEimTransactionIDProfileDownloadTrigger(t *testing.T) {
	t.Parallel()

	transactionID := []byte{0x05, 0x06}
	request := &protocolasn1.ProfileDownloadTriggerRequest{
		ProfileDownloadData: &protocolasn1.ProfileDownloadData{
			Kind:           protocolasn1.ProfileDownloadActivationCode,
			ActivationCode: "1$example.com$ACT",
		},
		EimTransactionID: transactionID,
	}
	operation := storage.Operation{
		Kind:    storage.OperationProfileDownloadTrigger,
		Payload: encode(t, request),
	}

	matched, err := OperationMatchesEimTransactionID(operation, transactionID)
	if err != nil {
		t.Fatalf("OperationMatchesEimTransactionID() error = %v", err)
	}
	if !matched {
		t.Fatalf("OperationMatchesEimTransactionID() = false, want true")
	}
	matched, err = OperationMatchesEimTransactionID(operation, []byte{0x07})
	if err != nil {
		t.Fatalf("OperationMatchesEimTransactionID(mismatch) error = %v", err)
	}
	if matched {
		t.Fatalf("OperationMatchesEimTransactionID(mismatch) = true, want false")
	}
}
