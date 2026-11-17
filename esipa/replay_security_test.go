// Replay and unsigned-result hardening regression tests. Reported by Adam Bedard,
// Security Researcher.
package esipa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	"github.com/openiotrsp/openiotrsp/pki"
	signingfile "github.com/openiotrsp/openiotrsp/signing/file"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

// Research reproduction: a captured, valid EPR for a completed operation should
// not roll back the eIM's newer view of the same profile.
func TestResearchOldSignedResultReplaysAfterNewerOperation(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	fixture, err := pki.LoadSGP26VariantONISTMaterial("")
	if err != nil {
		t.Fatal(err)
	}
	eid := fixture.EID
	eidValue, err := hex.DecodeString(eid)
	if err != nil {
		t.Fatal(err)
	}
	iccid := []byte{0x89, 0x10}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{EID: eid, ICCID: hex.EncodeToString(iccid), IsEnabled: false}); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewStaticEUICCCertificateResolver(fixture.CICertificate, fixture.EUMCertificate, fixture.EUICCCertificate, pki.WithCurrentTime(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.EUICCPublicKey = resolver

	makeResult := func(op protocolasn1.PsmoOperation, counter int64, txn byte, resultTag uint64) ([]byte, int64) {
		request := samplePSMOEuiccPackageRequest(eidValue, op, 3)
		request.EuiccPackageSigned.EuiccPackage.PSMOs[0].ICCID = cloneBytes(iccid)
		request.EuiccPackageSigned.CounterValue = counter
		request.EuiccPackageSigned.EimTransactionID = []byte{txn}
		queued, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{EID: eid, Kind: storage.OperationEuiccPackage, Payload: encode(t, request)})
		if err != nil {
			t.Fatal(err)
		}
		return signedEUICCPackageResult(t, fixture.EUICCKey, request, counter+10, resultTag, 0), queued.ID
	}
	submit := func(result []byte) error {
		payload := encodeEnvelope(t, &protocolasn1.ProvideEimPackageResult{EID: eidValue, EimPackageResult: protocolasn1.EimPackageResult{Raw: mustTLVFromDER(t, result)}})
		request := httptest.NewRequest(http.MethodPost, GSMAPathASN1, bytes.NewReader(payload))
		request.Header.Set("Content-Type", ASN1MediaType)
		response := httptest.NewRecorder()
		handler.HTTPHandler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			return fmt.Errorf("ESipa HTTP status %d: %s", response.Code, response.Body.String())
		}
		return nil
	}
	state := func() bool {
		profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eid, hex.EncodeToString(iccid))
		if err != nil {
			t.Fatal(err)
		}
		return profile.IsEnabled
	}
	status := func(id int64) storage.OperationStatus {
		operation, err := store.GetOperation(ctx, storage.DefaultTenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		return operation.Status
	}

	enableResult, enableID := makeResult(protocolasn1.PsmoEnable, 1, 0x11, 3)
	if err := submit(enableResult); err != nil {
		t.Fatalf("valid enable: %v", err)
	}
	if !state() || status(enableID) != storage.OperationDone {
		t.Fatal("valid enable not applied and completed")
	}
	// Negative control: an altered signature must fail and preserve state.
	tampered := cloneBytes(enableResult)
	tampered[len(tampered)-1] ^= 1
	if err := submit(tampered); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("altered signature not rejected by signature check: %v", err)
	}
	if !state() || status(enableID) != storage.OperationDone {
		t.Fatal("altered signature changed state")
	}

	disableResult, disableID := makeResult(protocolasn1.PsmoDisable, 2, 0x22, 4)
	if err := submit(disableResult); err != nil {
		t.Fatalf("valid disable: %v", err)
	}
	if state() || status(disableID) != storage.OperationDone {
		t.Fatal("valid disable not applied and completed")
	}
	// Replay the byte-identical signed enable result after disable must ack
	// idempotently without rolling back the newer disable.
	if err := submit(enableResult); err != nil {
		t.Fatalf("old signed result replay rejected: %v", err)
	}
	if state() {
		t.Fatal("old signed result replay rolled back newer disable state")
	}
	if status(enableID) != storage.OperationDone || status(disableID) != storage.OperationDone {
		t.Fatal("replay unexpectedly changed operation completion statuses")
	}
	t.Logf("observed: valid enable op=%d counter=1 txn=11 -> enabled; tampered signature -> HTTP 400; valid disable op=%d counter=2 txn=22 -> disabled; replayed byte-identical old enable -> HTTP 200 and profile stays disabled (both operations done)", enableID, disableID)
}

// A completed deleteEim result can be replayed after a later addEim, removing
// the later association from the eIM's database while the eUICC is untouched.
func TestResearchOldDeleteEIMResultRemovesNewAssociation(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	fixture, err := pki.LoadSGP26VariantONISTMaterial("")
	if err != nil {
		t.Fatal(err)
	}
	eid := fixture.EID
	eidValue, err := hex.DecodeString(eid)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewStaticEUICCCertificateResolver(fixture.CICertificate, fixture.EUMCertificate, fixture.EUICCCertificate, pki.WithCurrentTime(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	eimSigner, err := signingfile.NewFromECDSA(fixture.EIMKey, fixture.EIMCertificate)
	if err != nil {
		t.Fatal(err)
	}
	const issuerID = "testeim1"
	const targetID = "other.eim.example"
	issuerConfig, err := euiccpkg.NewEIMConfigurationDataFromCertificate(issuerID, "issuer.eim.example", 1, fixture.EIMCertificate)
	if err != nil {
		t.Fatal(err)
	}
	issuerToken := int64(7)
	issuerConfig.AssociationToken = &issuerToken
	if err := euiccpkg.RecordInitialEIMAssociation(ctx, store, storage.DefaultTenantID, eid, issuerConfig); err != nil {
		t.Fatal(err)
	}
	targetConfig, err := euiccpkg.NewEIMConfigurationDataFromCertificate(targetID, targetID, 1, fixture.EIMCertificate)
	if err != nil {
		t.Fatal(err)
	}
	wantNewToken := int64(-1)
	targetConfig.AssociationToken = &wantNewToken
	service := &euiccpkg.Service{Store: store, Signer: eimSigner, EimID: issuerID}
	handler := NewHandler(store, storage.DefaultTenantID)
	handler.EUICCPublicKey = resolver

	queue := func(txn byte, pkg protocolasn1.EuiccPackage) (*euiccpkg.SignedRequest, int64) {
		signed, err := service.Sign(ctx, euiccpkg.SignInput{TenantID: storage.DefaultTenantID, EID: eid, EIDValue: eidValue, EimTransactionID: []byte{txn}, Package: pkg})
		if err != nil {
			t.Fatal(err)
		}
		operation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{EID: eid, Kind: storage.OperationEuiccPackage, Payload: signed.DER})
		if err != nil {
			t.Fatal(err)
		}
		return signed, operation.ID
	}
	send := func(result []byte) error {
		payload := encodeEnvelope(t, &protocolasn1.ProvideEimPackageResult{EID: eidValue, EimPackageResult: protocolasn1.EimPackageResult{Raw: mustTLVFromDER(t, result)}})
		request := httptest.NewRequest(http.MethodPost, GSMAPathASN1, bytes.NewReader(payload))
		request.Header.Set("Content-Type", ASN1MediaType)
		response := httptest.NewRecorder()
		handler.HTTPHandler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			return fmt.Errorf("ESipa HTTP status %d: %s", response.Code, response.Body.String())
		}
		return nil
	}
	associationToken := func() (int64, error) {
		associated, err := store.GetAssociatedEIM(ctx, storage.DefaultTenantID, eid, targetID)
		if err != nil {
			return 0, err
		}
		var config protocolasn1.EimConfigurationData
		if err := protocolasn1.Decode(associated.ConfigPayload, &config); err != nil {
			return 0, err
		}
		if config.AssociationToken == nil {
			return 0, errors.New("missing target association token")
		}
		return *config.AssociationToken, nil
	}

	firstAdd, firstAddID := queue(0x31, euiccpkg.AddEIM(targetConfig))
	firstToken := int64(42)
	firstArm, err := protocolasn1.AddEimEuiccResult(&protocolasn1.AddEimResult{AssociationToken: &firstToken})
	if err != nil {
		t.Fatal(err)
	}
	firstAddResult := researchSignedResultWithToken(t, fixture.EUICCKey, &firstAdd.Request, 31, firstArm, issuerToken)
	if err := send(firstAddResult); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if token, err := associationToken(); err != nil || token != 42 {
		t.Fatalf("first association token=%d err=%v", token, err)
	}

	deleteReq, deleteID := queue(0x32, euiccpkg.DeleteEIM(targetID))
	deleteArm, err := protocolasn1.IntegerEuiccResult(9, 0)
	if err != nil {
		t.Fatal(err)
	}
	deleteResult := researchSignedResultWithToken(t, fixture.EUICCKey, &deleteReq.Request, 32, deleteArm, issuerToken)
	if err := send(deleteResult); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := associationToken(); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("target association after delete: %v", err)
	}

	secondAdd, secondAddID := queue(0x33, euiccpkg.AddEIM(targetConfig))
	if firstAdd.CounterValue >= deleteReq.CounterValue || deleteReq.CounterValue >= secondAdd.CounterValue {
		t.Fatalf("request counters not increasing: %d, %d, %d", firstAdd.CounterValue, deleteReq.CounterValue, secondAdd.CounterValue)
	}
	secondToken := int64(43)
	secondArm, err := protocolasn1.AddEimEuiccResult(&protocolasn1.AddEimResult{AssociationToken: &secondToken})
	if err != nil {
		t.Fatal(err)
	}
	secondAddResult := researchSignedResultWithToken(t, fixture.EUICCKey, &secondAdd.Request, 33, secondArm, issuerToken)
	if err := send(secondAddResult); err != nil {
		t.Fatalf("second add: %v", err)
	}
	if token, err := associationToken(); err != nil || token != 43 {
		t.Fatalf("new association token=%d err=%v", token, err)
	}

	tamperedDelete := cloneBytes(deleteResult)
	tamperedDelete[len(tamperedDelete)-1] ^= 1
	if err := send(tamperedDelete); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("tampered stale delete not rejected by signature check: %v", err)
	}
	if token, err := associationToken(); err != nil || token != 43 {
		t.Fatalf("tampered delete changed new association token=%d err=%v", token, err)
	}

	if err := send(deleteResult); err != nil {
		t.Fatalf("old signed delete replay rejected: %v", err)
	}
	if token, err := associationToken(); err != nil || token != 43 {
		t.Fatalf("stale delete replay removed newer association token=%d err=%v", token, err)
	}
	sequences := make([]int64, 0, 3)
	for _, id := range []int64{firstAddID, deleteID, secondAddID} {
		operation, err := store.GetOperation(ctx, storage.DefaultTenantID, id)
		if err != nil || operation.Status != storage.OperationDone {
			t.Fatalf("operation %d status=%s err=%v", id, operation.Status, err)
		}
		sequences = append(sequences, operation.SequenceNumber)
	}
	if sequences[0] >= sequences[1] || sequences[1] >= sequences[2] {
		t.Fatalf("operation sequences not increasing: %v", sequences)
	}
	t.Logf("observed: signed add op=%d seq=%d counter=%d -> target token 42; signed delete op=%d seq=%d counter=%d -> absent; signed re-add op=%d seq=%d counter=%d -> token 43; tampered old delete -> HTTP 400 and token 43 preserved; replay byte-identical old signed delete -> HTTP 200 and token 43 preserved (all operations done)", firstAddID, sequences[0], firstAdd.CounterValue, deleteID, sequences[1], deleteReq.CounterValue, secondAddID, sequences[2], secondAdd.CounterValue)
}

func researchSignedResultWithToken(t *testing.T, key *ecdsa.PrivateKey, request *protocolasn1.EuiccPackageRequest, cardSequence int64, arm protocolasn1.EuiccResultData, token int64) []byte {
	t.Helper()
	signed := protocolasn1.EuiccPackageResultDataSigned{
		EimID:            request.EuiccPackageSigned.EimID,
		CounterValue:     request.EuiccPackageSigned.CounterValue,
		EimTransactionID: cloneBytes(request.EuiccPackageSigned.EimTransactionID),
		SeqNumber:        cardSequence,
		Results:          []protocolasn1.EuiccResultData{arm},
	}
	input, err := euiccpkg.SignatureInput(encode(t, &signed), &token)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return encode(t, &protocolasn1.EuiccPackageResult{Kind: protocolasn1.EuiccPackageResultOK, Signed: &protocolasn1.EuiccPackageResultSigned{Data: signed, EuiccSignEPR: signature}})
}
