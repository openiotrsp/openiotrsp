package esipa

// IPA eimPackageError must not close or reopen euicc-package operations when
// eUICC result verification is enabled. Reported by Adam Bedard, Security
// Researcher, against v0.2.29. All identities and state are local/synthetic.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	"github.com/openiotrsp/openiotrsp/pki"
	signingfile "github.com/openiotrsp/openiotrsp/signing/file"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestRetestIPAErrorLeavesPendingOperation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		withTxn bool
	}{
		{"matching transaction ID", true},
		{"no transaction ID", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, err := pki.LoadSGP26VariantONISTMaterial("")
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := NewStaticEUICCCertificateResolver(
				fixture.CICertificate, fixture.EUMCertificate, fixture.EUICCCertificate,
				pki.WithCurrentTime(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)),
			)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			store := memory.New()
			eid, err := hex.DecodeString(fixture.EID)
			if err != nil {
				t.Fatal(err)
			}
			eidKey := hex.EncodeToString(eid)
			if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eidKey}); err != nil {
				t.Fatal(err)
			}
			cert := testCertificate(t)
			signer, err := signingfile.NewFromECDSA(cert.PrivateKey.(*ecdsa.PrivateKey), cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			signed, err := (&euiccpkg.Service{Store: store, Signer: signer, EimID: "testeim1"}).Sign(ctx,
				euiccpkg.SignInput{
					TenantID:         storage.DefaultTenantID,
					EID:              eidKey,
					EIDValue:         eid,
					EimTransactionID: []byte{0xaa, 0xbb, 0xcc, 0xdd},
					Package:          euiccpkg.Enable([]byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1}, false),
				})
			if err != nil {
				t.Fatal(err)
			}
			op, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
				EID: eidKey, Kind: storage.OperationEuiccPackage, Payload: signed.DER,
			})
			if err != nil {
				t.Fatal(err)
			}
			handler := NewHandler(store, storage.DefaultTenantID)
			handler.EUICCPublicKey = resolver
			server := httptest.NewTLSServer(handler.HTTPHandler())
			defer server.Close()

			polled := decodeGetResponse(t, postASN1(t, server, encodeEnvelope(t,
				&protocolasn1.GetEimPackageRequest{EID: eid})))
			if polled.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
				t.Fatalf("poll kind=%v, expected queued package", polled.Kind)
			}
			ipaErr := &protocolasn1.EimPackageResultResponseError{Code: 127}
			if tc.withTxn {
				ipaErr.EimTransactionID = polled.EuiccPackageRequest.EuiccPackageSigned.EimTransactionID
			}
			postASN1(t, server, encodeEnvelope(t, &protocolasn1.ProvideEimPackageResult{
				EID:              eid,
				EimPackageResult: protocolasn1.EimPackageResult{Kind: protocolasn1.EimPackageResultError, Error: ipaErr},
			}))
			after, err := store.GetOperation(ctx, storage.DefaultTenantID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eidKey, 10)
			if err != nil {
				t.Fatal(err)
			}
			next := decodeGetResponse(t, postASN1(t, server, encodeEnvelope(t,
				&protocolasn1.GetEimPackageRequest{EID: eid})))
			t.Logf("unsigned IPA eimPackageError (%s): operation=%s pending=%d next-poll-kind=%v",
				tc.name, after.Status, len(pending), next.Kind)
			if after.Status != storage.OperationPending {
				t.Fatalf("operation closed: status=%s", after.Status)
			}
			if len(pending) != 1 || pending[0].ID != op.ID {
				t.Fatalf("pending = %#v, want operation %d still queued", pending, op.ID)
			}
			if next.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
				t.Fatalf("next poll kind=%v, want the same queued package", next.Kind)
			}
		})
	}
}

func TestRetestReplayAfterIPAErrorKeepsCompletedOperation(t *testing.T) {
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
	post := func(result protocolasn1.EimPackageResult) error {
		payload := encodeEnvelope(t, &protocolasn1.ProvideEimPackageResult{EID: eidValue, EimPackageResult: result})
		request := httptest.NewRequest(http.MethodPost, GSMAPathASN1, bytes.NewReader(payload))
		request.Header.Set("Content-Type", ASN1MediaType)
		response := httptest.NewRecorder()
		handler.HTTPHandler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			return fmt.Errorf("ESipa HTTP status %d: %s", response.Code, response.Body.String())
		}
		return nil
	}
	submit := func(result []byte) error {
		return post(protocolasn1.EimPackageResult{Raw: mustTLVFromDER(t, result)})
	}
	enabled := func() bool {
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
	disableResult, disableID := makeResult(protocolasn1.PsmoDisable, 2, 0x22, 4)
	if err := submit(disableResult); err != nil {
		t.Fatalf("valid disable: %v", err)
	}
	if enabled() || status(enableID) != storage.OperationDone || status(disableID) != storage.OperationDone {
		t.Fatal("setup: expected profile disabled and both operations done")
	}

	if err := submit(enableResult); err != nil {
		t.Fatalf("direct replay: %v", err)
	}
	if enabled() {
		t.Fatal("direct replay rolled back state")
	}
	t.Logf("control: direct replay of old enable -> HTTP 200, profile stays disabled, enable op=%s", status(enableID))

	if err := post(protocolasn1.EimPackageResult{
		Kind:  protocolasn1.EimPackageResultError,
		Error: &protocolasn1.EimPackageResultResponseError{EimTransactionID: []byte{0x11}, Code: 127},
	}); err != nil {
		t.Fatalf("IPA error: %v", err)
	}
	t.Logf("after unsigned IPA eimPackageError txn=11: enable op=%s disable op=%s profile enabled=%v", status(enableID), status(disableID), enabled())
	if status(enableID) != storage.OperationDone || status(disableID) != storage.OperationDone || enabled() {
		t.Fatal("IPA error changed a completed operation or profile state")
	}

	if err := submit(enableResult); err != nil {
		t.Fatalf("replay after IPA error: %v", err)
	}
	t.Logf("after replaying old signed enable: enable op=%s disable op=%s profile enabled=%v", status(enableID), status(disableID), enabled())
	if enabled() {
		t.Fatal("replay after IPA error rolled the profile back to enabled")
	}
	if status(enableID) != storage.OperationDone || status(disableID) != storage.OperationDone {
		t.Fatal("replay after IPA error changed operation status")
	}
}
