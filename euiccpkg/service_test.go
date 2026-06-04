package euiccpkg

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdasn1 "encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestConstructSignVerifyAndApplyPSMOOperations(t *testing.T) {
	t.Parallel()

	type operationCase struct {
		name       string
		makePkg    func([]byte) protocolasn1.EuiccPackage
		resultTag  uint64
		initial    bool
		wantStatus *bool
	}

	disabled := false
	enabled := true
	cases := []operationCase{
		{name: "enable", makePkg: func(iccid []byte) protocolasn1.EuiccPackage { return Enable(iccid, false) }, resultTag: 3, initial: disabled, wantStatus: &enabled},
		{name: "disable", makePkg: Disable, resultTag: 4, initial: enabled, wantStatus: &disabled},
		{name: "delete", makePkg: Delete, resultTag: 5, initial: disabled, wantStatus: nil},
	}

	for index, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store := memory.New()
			eimSigner := newTestSigner(t)
			euiccSigner := newTestSigner(t)
			service := &Service{Store: store, Signer: eimSigner, EimID: "eim.example"}
			eid := "eid-" + tc.name
			eidValue := testEID(byte(index + 1))
			iccid := []byte{0x89, 0x10, byte(index + 1)}
			registerWithState(t, store, eid, storage.ProfileState{
				EID:       eid,
				ICCID:     hex.EncodeToString(iccid),
				IsEnabled: tc.initial,
			})

			request := signPackage(t, ctx, service, eid, eidValue, []byte{0x01, byte(index)}, tc.makePkg(iccid))
			verifyEIMSignature(t, eimSigner.PublicKey(), request)
			assertRequestRoundTrip(t, request.DER)

			operation, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
				EID:     eid,
				Kind:    storage.OperationEuiccPackage,
				Payload: request.DER,
			})
			if err != nil {
				t.Fatalf("EnqueueOperation() error = %v", err)
			}
			resultDER := signedResultDER(t, euiccSigner, request, operation.SequenceNumber, tc.resultTag, 0)

			result, err := service.VerifyAndApplyResult(ctx, ResultInput{
				Request:        request,
				ResultDER:      resultDER,
				EUICCPublicKey: euiccSigner.PublicKey(),
				OperationID:    operation.ID,
				SequenceNumber: operation.SequenceNumber,
			})
			if err != nil {
				t.Fatalf("VerifyAndApplyResult() error = %v", err)
			}
			if !result.OK || result.ResultCode != ResultOK {
				t.Fatalf("result = %#v, want ok", result)
			}
			assertProfileEnabled(t, store, eid, iccid, tc.wantStatus)
		})
	}
}

func TestCounterMonotonicityPersistsAcrossServiceRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-counter"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	service := &Service{Store: store, Signer: newTestSigner(t), EimID: "eim.example"}
	first := signPackage(t, ctx, service, eid, testEID(1), nil, Enable([]byte{0x89, 0x10}, false))
	second := signPackage(t, ctx, service, eid, testEID(1), nil, Disable([]byte{0x89, 0x10}))

	restartedService := &Service{Store: store, Signer: newTestSigner(t), EimID: "eim.example"}
	third := signPackage(t, ctx, restartedService, eid, testEID(1), nil, Delete([]byte{0x89, 0x10}))

	if got := []int64{first.CounterValue, second.CounterValue, third.CounterValue}; !equalInt64s(got, []int64{1, 2, 3}) {
		t.Fatalf("counters = %v, want [1 2 3]", got)
	}
}

func TestConcurrentCounterConstruction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-concurrent-counter"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	service := &Service{Store: store, Signer: newTestSigner(t), EimID: "eim.example"}

	const count = 64
	var wg sync.WaitGroup
	wg.Add(count)
	errs := make(chan error, count)
	counters := make(chan int64, count)
	for index := range count {
		index := index
		go func() {
			defer wg.Done()
			request, err := service.Sign(ctx, SignInput{
				TenantID: storage.DefaultTenantID,
				EID:      eid,
				EIDValue: testEID(2),
				Package:  Enable([]byte{0x89, 0x10, byte(index)}, false),
			})
			if err != nil {
				errs <- err
				return
			}
			counters <- request.CounterValue
		}()
	}
	wg.Wait()
	close(errs)
	close(counters)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[int64]bool, count)
	for counter := range counters {
		if counter < 1 || counter > count {
			t.Fatalf("counter %d outside 1..%d", counter, count)
		}
		if seen[counter] {
			t.Fatalf("duplicate counter %d", counter)
		}
		seen[counter] = true
	}
	if len(seen) != count {
		t.Fatalf("saw %d counters, want %d", len(seen), count)
	}
}

func TestReplayLowerCounterResultRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-replay"
	registerWithState(t, store, eid)
	service := &Service{Store: store, Signer: newTestSigner(t), EimID: "eim.example"}
	euiccSigner := newTestSigner(t)

	first := signPackage(t, ctx, service, eid, testEID(3), []byte{0x01}, Enable([]byte{0x89, 0x10}, false))
	second := signPackage(t, ctx, service, eid, testEID(3), []byte{0x02}, Disable([]byte{0x89, 0x10}))
	resultDER := signedResultDERWithCounter(t, euiccSigner, second, 1, 4, 0, first.CounterValue)

	_, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        second,
		ResultDER:      resultDER,
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 1,
	})
	if !errors.Is(err, ErrCounterMismatch) {
		t.Fatalf("VerifyAndApplyResult() error = %v, want %v", err, ErrCounterMismatch)
	}
}

func TestVerifyUsesRawSignedResultBytes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-raw-signed-result"
	iccid := []byte{0x89, 0x10, 0xab}
	registerWithState(t, store, eid, storage.ProfileState{
		EID:       eid,
		ICCID:     hex.EncodeToString(iccid),
		IsEnabled: false,
	})
	service := &Service{Store: store, Signer: newTestSigner(t), EimID: "eim.example"}
	euiccSigner := newTestSigner(t)
	request := signPackage(t, ctx, service, eid, testEID(9), []byte{0x44}, Enable(iccid, false))

	resultData, err := protocolasn1.IntegerEuiccResult(3, 0)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	data := protocolasn1.EuiccPackageResultDataSigned{
		EimID:            request.EimID,
		CounterValue:     request.CounterValue,
		EimTransactionID: cloneBytes(request.EimTransactionID),
		SeqNumber:        1,
		Results:          []protocolasn1.EuiccResultData{resultData},
	}
	canonicalSignedData := encode(t, &data)
	wireSignedData := withLongFormLength(t, canonicalSignedData)
	signature := signRawBytes(t, euiccSigner, wireSignedData)
	assertSignatureRejected(t, euiccSigner.PublicKey(), canonicalSignedData, signature)
	resultDER := wrapSignedResultTLV(wireSignedData, signature)

	result, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        request,
		ResultDER:      resultDER,
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 1,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult() error = %v", err)
	}
	if !result.OK || result.Operation != OperationEnable {
		t.Fatalf("result = %#v, want successful enable", result)
	}
	assertProfileEnabled(t, store, eid, iccid, boolPtr(true))
}

func TestRawSignedDataFromResultDERRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	validSignedData := []byte{0x30, 0x03, 0x80, 0x01, 0x78}
	validSignature := makeTLV([]byte{0x5f, 0x37}, []byte{0x01})
	validSignedResult := makeTLV([]byte{0x30}, append(cloneBytes(validSignedData), validSignature...))
	validResult := makeTLV([]byte{0xbf, 0x51}, validSignedResult)

	cases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "wrong root tag", data: makeTLV([]byte{0xbf, 0x52}, validSignedResult)},
		{name: "truncated root length", data: []byte{0xbf, 0x51, 0x81}},
		{name: "truncated root value", data: []byte{0xbf, 0x51, 0x04, 0x30, 0x02}},
		{name: "trailing data", data: append(cloneBytes(validResult), 0x00)},
		{name: "multiple selected children", data: makeTLV([]byte{0xbf, 0x51}, append(cloneBytes(validSignedResult), validSignedResult...))},
		{name: "empty signed sequence", data: makeTLV([]byte{0xbf, 0x51}, []byte{0x30, 0x00})},
		{name: "indefinite length", data: []byte{0xbf, 0x51, 0x80, 0x00, 0x00}},
		{name: "oversized length octets", data: []byte{0xbf, 0x51, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("rawSignedDataFromResultDER() panicked: %v", recovered)
				}
			}()
			if raw, err := rawSignedDataFromResultDER(tc.data); err == nil {
				t.Fatalf("rawSignedDataFromResultDER() = %x, nil; want error", raw)
			}
		})
	}
}

func TestRawSignedDataFromResultDERAnchorsToResultSignedData(t *testing.T) {
	t.Parallel()

	resultData, err := protocolasn1.IntegerEuiccResult(3, 0)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	okSignedData := encode(t, &protocolasn1.EuiccPackageResultDataSigned{
		EimID:        "testeim1",
		CounterValue: 1,
		SeqNumber:    1,
		Results:      []protocolasn1.EuiccResultData{resultData},
	})
	raw, err := rawSignedDataFromResultDER(wrapSignedResultTLV(okSignedData, []byte{0x30, 0x00}))
	if err != nil {
		t.Fatalf("rawSignedDataFromResultDER(ok) error = %v", err)
	}
	if !bytes.Equal(raw, okSignedData) {
		t.Fatalf("raw signed result data = %x, want %x", raw, okSignedData)
	}

	errorSignedData := encode(t, &protocolasn1.EuiccPackageErrorDataSigned{
		EimID:        "testeim1",
		CounterValue: 1,
		ErrorCode:    3,
	})
	raw, err = rawSignedDataFromResultDER(wrapSignedResultTLV(errorSignedData, []byte{0x30, 0x00}))
	if err != nil {
		t.Fatalf("rawSignedDataFromResultDER(error) error = %v", err)
	}
	if !bytes.Equal(raw, errorSignedData) {
		t.Fatalf("raw signed error data = %x, want %x", raw, errorSignedData)
	}

	requestSignedData := encode(t, &protocolasn1.EuiccPackageSigned{
		EimID:        "testeim1",
		EID:          testEID(1),
		CounterValue: 1,
		EuiccPackage: Enable([]byte{0x89, 0x10}, false),
	})
	if raw, err := rawSignedDataFromResultDER(wrapSignedResultTLV(requestSignedData, []byte{0x30, 0x00})); err == nil {
		t.Fatalf("rawSignedDataFromResultDER(request-shaped data) = %x, nil; want error", raw)
	}
}

func TestResultAndPackageErrorsDoNotChangeState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-errors"
	iccid := []byte{0x89, 0x10, 0xee}
	registerWithState(t, store, eid, storage.ProfileState{EID: eid, ICCID: hex.EncodeToString(iccid), IsEnabled: false})
	service := &Service{Store: store, Signer: newTestSigner(t), EimID: "eim.example"}
	euiccSigner := newTestSigner(t)
	request := signPackage(t, ctx, service, eid, testEID(4), []byte{0x9a}, Enable(iccid, false))

	operationErrors := map[int64]ResultCode{
		1:   ResultICCIDOrAIDNotFound,
		2:   ResultProfileNotInDisabledState,
		3:   ResultDisallowedByPolicy,
		5:   ResultCatBusy,
		20:  ResultRollbackNotAvailable,
		127: ResultUndefinedError,
	}
	for raw, mapped := range operationErrors {
		resultDER := signedResultDER(t, euiccSigner, request, 0, 3, raw)
		result, err := service.VerifyAndApplyResult(ctx, ResultInput{
			Request:        request,
			ResultDER:      resultDER,
			EUICCPublicKey: euiccSigner.PublicKey(),
		})
		if err != nil {
			t.Fatalf("operation result %d: VerifyAndApplyResult() error = %v", raw, err)
		}
		if result.OK || result.ResultCode != mapped {
			t.Fatalf("operation result %d mapped to %#v, want %s", raw, result, mapped)
		}
		assertProfileEnabled(t, store, eid, iccid, boolPtr(false))
	}

	packageErrors := map[int64]PackageError{
		3:   PackageErrorInvalidEID,
		4:   PackageErrorReplay,
		6:   PackageErrorCounterValueOutOfRange,
		15:  PackageErrorSizeOverflow,
		104: PackageErrorECallActive,
		127: PackageErrorUndefined,
	}
	for raw, mapped := range packageErrors {
		resultDER := signedPackageErrorDER(t, euiccSigner, request, raw)
		result, err := service.VerifyAndApplyResult(ctx, ResultInput{
			Request:        request,
			ResultDER:      resultDER,
			EUICCPublicKey: euiccSigner.PublicKey(),
		})
		if err != nil {
			t.Fatalf("package error %d: VerifyAndApplyResult() error = %v", raw, err)
		}
		if result.OK || result.PackageError != mapped {
			t.Fatalf("package error %d mapped to %#v, want %s", raw, result, mapped)
		}
		assertProfileEnabled(t, store, eid, iccid, boolPtr(false))
	}

	unsignedErrors := map[int64]UnsignedPackageError{
		15:  UnsignedPackageErrorSizeOverflow,
		127: UnsignedPackageErrorUndefined,
	}
	for raw, mapped := range unsignedErrors {
		resultDER := unsignedPackageErrorDER(t, request, raw)
		result, err := service.VerifyAndApplyResult(ctx, ResultInput{
			Request:        request,
			ResultDER:      resultDER,
			EUICCPublicKey: euiccSigner.PublicKey(),
		})
		if err != nil {
			t.Fatalf("unsigned package error %d: VerifyAndApplyResult() error = %v", raw, err)
		}
		if result.OK || result.UnsignedPackageError != mapped {
			t.Fatalf("unsigned package error %d mapped to %#v, want %s", raw, result, mapped)
		}
		assertProfileEnabled(t, store, eid, iccid, boolPtr(false))
	}
}

func TestECOConstructorsEncode(t *testing.T) {
	t.Parallel()

	config := &protocolasn1.EimConfigurationData{EimID: "other.eim"}
	cases := []struct {
		name string
		pkg  protocolasn1.EuiccPackage
	}{
		{name: "add", pkg: AddEIM(config)},
		{name: "delete", pkg: DeleteEIM("other.eim")},
		{name: "update", pkg: UpdateEIM(config)},
		{name: "list", pkg: ListEIM()},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := protocolasn1.Encode(&tc.pkg)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			var decoded protocolasn1.EuiccPackage
			if err := protocolasn1.Decode(encoded, &decoded); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			reencoded, err := protocolasn1.Encode(&decoded)
			if err != nil {
				t.Fatalf("re-Encode() error = %v", err)
			}
			if !bytes.Equal(reencoded, encoded) {
				t.Fatalf("ECO re-encode mismatch\n got %x\nwant %x", reencoded, encoded)
			}
		})
	}
}

func TestPSMOConstructorsEncode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		pkg  protocolasn1.EuiccPackage
	}{
		{name: "list profile info", pkg: ListProfileInfo()},
		{name: "get rat", pkg: GetRAT()},
		{name: "configure immediate enable", pkg: ConfigureImmediateEnable(true, stdasn1.ObjectIdentifier{1, 2, 840, 113549}, "smdp.example")},
		{name: "set fallback", pkg: SetFallbackAttribute([]byte{0x89, 0x10})},
		{name: "unset fallback", pkg: UnsetFallbackAttribute()},
		{name: "set default dp address", pkg: SetDefaultDPAddress("smdp.example")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := protocolasn1.Encode(&tc.pkg)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			var decoded protocolasn1.EuiccPackage
			if err := protocolasn1.Decode(encoded, &decoded); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			reencoded, err := protocolasn1.Encode(&decoded)
			if err != nil {
				t.Fatalf("re-Encode() error = %v", err)
			}
			if !bytes.Equal(reencoded, encoded) {
				t.Fatalf("PSMO re-encode mismatch\n got %x\nwant %x", reencoded, encoded)
			}
			operation, _ := packagePSMO(decoded)
			if operation == OperationNone {
				t.Fatalf("packagePSMO() = none for %s", tc.name)
			}
		})
	}
}

func TestSignatureInputIncludesAssociationToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-association-token"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	service := &Service{Store: store, Signer: newTestSigner(t), EimID: "eim.example"}

	zeroToken := signPackage(t, ctx, service, eid, testEID(1), nil, Enable([]byte{0x89, 0x10}, false))
	assertSignatureInputSuffix(t, zeroToken, []byte{0x84, 0x01, 0x00})
	verifyEIMSignature(t, service.Signer.PublicKey(), zeroToken)

	associationToken := int64(7)
	config := protocolasn1.EimConfigurationData{
		EimID:            service.EimID,
		AssociationToken: &associationToken,
	}
	payload := encode(t, &config)
	if err := store.SetAssociatedEIM(ctx, storage.DefaultTenantID, storage.AssociatedEIM{
		EID:           eid,
		EIMID:         service.EimID,
		ConfigPayload: payload,
	}); err != nil {
		t.Fatalf("SetAssociatedEIM() error = %v", err)
	}
	nonZeroToken := signPackage(t, ctx, service, eid, testEID(1), nil, Disable([]byte{0x89, 0x10}))
	assertSignatureInputSuffix(t, nonZeroToken, []byte{0x84, 0x01, 0x07})
	verifyEIMSignature(t, service.Signer.PublicKey(), nonZeroToken)
}

func TestSignatureInputAssociationTokenKnownAnswer(t *testing.T) {
	t.Parallel()

	// EuiccPackageSigned from the independent EuiccPackageRequest known-answer
	// fixture in asn1/sgp32_test.go, whose full request DER was generated outside
	// this encoder and validated with `openssl asn1parse -inform DER`.
	signedDER := mustDecodeHex(t, "3014800365696d5a020102810101a006a3045a029810")
	zero := int64(0)
	seven := int64(7)
	cases := []struct {
		name  string
		token *int64
		want  []byte
	}{
		{name: "no token", token: nil, want: mustDecodeHex(t, "3014800365696d5a020102810101a006a3045a029810840100")},
		{name: "explicit zero token", token: &zero, want: mustDecodeHex(t, "3014800365696d5a020102810101a006a3045a029810840100")},
		{name: "non-zero token", token: &seven, want: mustDecodeHex(t, "3014800365696d5a020102810101a006a3045a029810840107")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := signatureInput(signedDER, tc.token)
			if err != nil {
				t.Fatalf("signatureInput() error = %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("signature input = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestSignAppendsAssociationTokenForAllPackageOperations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-all-association-token"
	registerWithState(t, store, eid)
	signer := newTestSigner(t)
	service := &Service{Store: store, Signer: signer, EimID: "eim.example"}
	config := testEIMConfiguration(t, "other.eim", 1, signer.PublicKey())
	packages := []struct {
		name string
		pkg  protocolasn1.EuiccPackage
	}{
		{name: "enable", pkg: Enable([]byte{0x89, 0x10}, false)},
		{name: "disable", pkg: Disable([]byte{0x89, 0x10})},
		{name: "delete profile", pkg: Delete([]byte{0x89, 0x10})},
		{name: "list profile info", pkg: ListProfileInfo()},
		{name: "get rat", pkg: GetRAT()},
		{name: "configure immediate enable", pkg: ConfigureImmediateEnable(true, stdasn1.ObjectIdentifier{1, 2, 840, 113549}, "smdp.example")},
		{name: "set fallback", pkg: SetFallbackAttribute([]byte{0x89, 0x10})},
		{name: "unset fallback", pkg: UnsetFallbackAttribute()},
		{name: "set default dp address", pkg: SetDefaultDPAddress("smdp.example")},
		{name: "add eim", pkg: AddEim(config)},
		{name: "update eim", pkg: UpdateEim(config)},
		{name: "delete eim", pkg: DeleteEim("other.eim")},
		{name: "list eim", pkg: ListEim()},
	}

	for index, tc := range packages {
		request := signPackage(t, ctx, service, eid, testEID(1), []byte{0x00, byte(index)}, tc.pkg)
		assertSignatureInputSuffix(t, request, []byte{0x84, 0x01, 0x00})
	}

	associationToken := int64(7)
	payload := encode(t, &protocolasn1.EimConfigurationData{
		EimID:            service.EimID,
		AssociationToken: &associationToken,
	})
	if err := store.SetAssociatedEIM(ctx, storage.DefaultTenantID, storage.AssociatedEIM{
		EID:           eid,
		EIMID:         service.EimID,
		ConfigPayload: payload,
	}); err != nil {
		t.Fatalf("SetAssociatedEIM() error = %v", err)
	}
	for index, tc := range packages {
		request := signPackage(t, ctx, service, eid, testEID(1), []byte{0x07, byte(index)}, tc.pkg)
		assertSignatureInputSuffix(t, request, []byte{0x84, 0x01, 0x07})
	}
}

func TestInitialEIMAssociationConsumesTokenForSigning(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "eid-initial-association"
	registerWithState(t, store, eid)
	eimSigner := newTestSigner(t)
	service := &Service{Store: store, Signer: eimSigner, EimID: "eim.example"}

	associationToken := int64(44)
	config, err := NewInitialEIMConfigurationDataFromPublicKey(service.EimID, "eim.example", 1, eimSigner.PublicKey(), &associationToken)
	if err != nil {
		t.Fatalf("NewInitialEIMConfigurationDataFromPublicKey() error = %v", err)
	}
	if err := RecordInitialEIMAssociation(ctx, store, storage.DefaultTenantID, eid, config); err != nil {
		t.Fatalf("RecordInitialEIMAssociation() error = %v", err)
	}
	assertAssociatedEIMToken(t, store, eid, service.EimID, associationToken)

	request := signPackage(t, ctx, service, eid, testEID(1), nil, Enable([]byte{0x89, 0x10}, false))
	assertSignatureInputSuffix(t, request, []byte{0x84, 0x01, 0x2c})
	verifyEIMSignature(t, eimSigner.PublicKey(), request)
}

func TestECOResultsMapAndApplyState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eimSigner := newTestSigner(t)
	euiccSigner := newTestSigner(t)
	service := &Service{Store: store, Signer: eimSigner, EimID: "eim.example"}
	eid := "eid-eco-results"
	registerWithState(t, store, eid)
	config := testEIMConfiguration(t, "other.eim", int64(1), eimSigner.PublicKey())

	addRequest := signPackage(t, ctx, service, eid, testEID(2), []byte{0x01}, AddEim(config))
	addToken := int64(42)
	addResultData, err := protocolasn1.AddEimEuiccResult(&protocolasn1.AddEimResult{AssociationToken: &addToken})
	if err != nil {
		t.Fatalf("AddEimEuiccResult() error = %v", err)
	}
	addResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        addRequest,
		ResultDER:      signedResultDataDER(t, euiccSigner, addRequest, 1, []protocolasn1.EuiccResultData{addResultData}, addRequest.CounterValue),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 1,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(add) error = %v", err)
	}
	if !addResult.OK || addResult.Operation != OperationAddEIM || addResult.AddEIMAssociationToken == nil || *addResult.AddEIMAssociationToken != addToken {
		t.Fatalf("add result = %#v, want association token %d", addResult, addToken)
	}
	assertAssociatedEIMToken(t, store, eid, "other.eim", addToken)

	updateConfig := testEIMConfiguration(t, "other.eim", int64(2), eimSigner.PublicKey())
	updateRequest := signPackage(t, ctx, service, eid, testEID(2), []byte{0x02}, UpdateEim(updateConfig))
	updateResultDER := signedResultDER(t, euiccSigner, updateRequest, 2, 10, 0)
	updateResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        updateRequest,
		ResultDER:      updateResultDER,
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 2,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(update) error = %v", err)
	}
	if !updateResult.OK || updateResult.Operation != OperationUpdateEIM {
		t.Fatalf("update result = %#v, want ok update", updateResult)
	}
	assertAssociatedEIMCounter(t, store, eid, "other.eim", 2)

	listRequest := signPackage(t, ctx, service, eid, testEID(2), []byte{0x03}, ListEim())
	idType := protocolasn1.EimIDTypeFQDN
	listResultData, err := protocolasn1.ListEimEuiccResult(&protocolasn1.ListEimResult{
		EimIDList: []protocolasn1.EimIDInfo{{EimID: "other.eim", EimIDType: &idType}},
	})
	if err != nil {
		t.Fatalf("ListEimEuiccResult() error = %v", err)
	}
	listResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        listRequest,
		ResultDER:      signedResultDataDER(t, euiccSigner, listRequest, 3, []protocolasn1.EuiccResultData{listResultData}, listRequest.CounterValue),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 3,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(list) error = %v", err)
	}
	if !listResult.OK || listResult.Operation != OperationListEIM || len(listResult.EIMs) != 1 || listResult.EIMs[0].EIMID != "other.eim" {
		t.Fatalf("list result = %#v, want other.eim", listResult)
	}

	deleteRequest := signPackage(t, ctx, service, eid, testEID(2), []byte{0x04}, DeleteEim("other.eim"))
	deleteResultDER := signedResultDER(t, euiccSigner, deleteRequest, 4, 9, 2)
	deleteResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        deleteRequest,
		ResultDER:      deleteResultDER,
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 4,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(delete) error = %v", err)
	}
	if !deleteResult.OK || deleteResult.Operation != OperationDeleteEIM || !deleteResult.LastEIMDeleted || deleteResult.ECOResultCode != ECOResultLastEIMDeleted {
		t.Fatalf("delete result = %#v, want lastEimDeleted", deleteResult)
	}
	if _, err := store.GetAssociatedEIM(ctx, storage.DefaultTenantID, eid, "other.eim"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetAssociatedEIM(deleted) error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestPSMOResultsMapAndApplyState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eimSigner := newTestSigner(t)
	euiccSigner := newTestSigner(t)
	service := &Service{Store: store, Signer: eimSigner, EimID: "eim.example"}
	eid := "eid-psmo-results"
	iccidA := []byte{0x89, 0x10, 0xaa}
	iccidB := []byte{0x89, 0x10, 0xbb}
	registerWithState(t, store, eid,
		storage.ProfileState{EID: eid, ICCID: hex.EncodeToString(iccidA), IsEnabled: false, SMDPAddress: "smdp-a.example"},
		storage.ProfileState{EID: eid, ICCID: "stale", IsEnabled: true},
	)

	listRequest := signPackage(t, ctx, service, eid, testEID(3), []byte{0x10}, ListProfileInfo())
	enabled := protocolasn1.ProfileStateEnabled
	disabled := protocolasn1.ProfileStateDisabled
	listResultData, err := protocolasn1.ProfileInfoListEuiccResult(&protocolasn1.ProfileInfoListResponse{
		Profiles: []protocolasn1.ProfileInfo{
			{ICCID: iccidA, ProfileState: &enabled, FallbackAttribute: true},
			{ICCID: iccidB, ProfileState: &disabled},
		},
	})
	if err != nil {
		t.Fatalf("ProfileInfoListEuiccResult() error = %v", err)
	}
	listResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        listRequest,
		ResultDER:      signedResultDataDER(t, euiccSigner, listRequest, 1, []protocolasn1.EuiccResultData{listResultData}, listRequest.CounterValue),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 1,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(list) error = %v", err)
	}
	if !listResult.OK || listResult.Operation != OperationListProfileInfo || len(listResult.Profiles) != 2 {
		t.Fatalf("list result = %#v, want two profiles", listResult)
	}
	assertProfileStateFull(t, store, eid, iccidA, true, true, "smdp-a.example")
	assertProfileStateFull(t, store, eid, iccidB, false, false, "")
	if _, err := store.GetProfileState(ctx, storage.DefaultTenantID, eid, "stale"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("stale profile error = %v, want %v", err, storage.ErrNotFound)
	}

	setFallbackRequest := signPackage(t, ctx, service, eid, testEID(3), []byte{0x11}, SetFallbackAttribute(iccidB))
	setFallbackResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        setFallbackRequest,
		ResultDER:      signedResultDER(t, euiccSigner, setFallbackRequest, 2, 13, 0),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 2,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(set fallback) error = %v", err)
	}
	if !setFallbackResult.OK || setFallbackResult.Operation != OperationSetFallbackAttribute {
		t.Fatalf("set fallback result = %#v, want ok", setFallbackResult)
	}
	assertProfileStateFull(t, store, eid, iccidA, true, false, "smdp-a.example")
	assertProfileStateFull(t, store, eid, iccidB, false, true, "")

	unsetFallbackRequest := signPackage(t, ctx, service, eid, testEID(3), []byte{0x12}, UnsetFallbackAttribute())
	unsetFallbackResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        unsetFallbackRequest,
		ResultDER:      signedResultDER(t, euiccSigner, unsetFallbackRequest, 3, 14, 0),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 3,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(unset fallback) error = %v", err)
	}
	if !unsetFallbackResult.OK || unsetFallbackResult.Operation != OperationUnsetFallbackAttribute {
		t.Fatalf("unset fallback result = %#v, want ok", unsetFallbackResult)
	}
	assertProfileStateFull(t, store, eid, iccidB, false, false, "")

	configureRequest := signPackage(t, ctx, service, eid, testEID(3), []byte{0x13}, ConfigureImmediateEnable(true, nil, "smdp.example"))
	configureResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        configureRequest,
		ResultDER:      signedResultDER(t, euiccSigner, configureRequest, 4, 7, 0),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 4,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(configure) error = %v", err)
	}
	if !configureResult.OK || configureResult.Operation != OperationConfigureImmediateEnable {
		t.Fatalf("configure result = %#v, want ok", configureResult)
	}

	ratRequest := signPackage(t, ctx, service, eid, testEID(3), []byte{0x14}, GetRAT())
	ratResultData := protocolasn1.EuiccResultData{Raw: mustTLV(t, []byte{0xa6, 0x00})}
	ratResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        ratRequest,
		ResultDER:      signedResultDataDER(t, euiccSigner, ratRequest, 5, []protocolasn1.EuiccResultData{ratResultData}, ratRequest.CounterValue),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 5,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(get RAT) error = %v", err)
	}
	if !ratResult.OK || ratResult.Operation != OperationGetRAT || ratResult.RulesAuthorisationTable == nil {
		t.Fatalf("RAT result = %#v, want raw RAT", ratResult)
	}

	defaultDPRequest := signPackage(t, ctx, service, eid, testEID(3), []byte{0x15}, SetDefaultDPAddress("smdp.example"))
	defaultDPResultData, err := protocolasn1.SetDefaultDPAddressEuiccResult(&protocolasn1.SetDefaultDPAddressResponse{Result: 0})
	if err != nil {
		t.Fatalf("SetDefaultDPAddressEuiccResult() error = %v", err)
	}
	defaultDPResult, err := service.VerifyAndApplyResult(ctx, ResultInput{
		Request:        defaultDPRequest,
		ResultDER:      signedResultDataDER(t, euiccSigner, defaultDPRequest, 6, []protocolasn1.EuiccResultData{defaultDPResultData}, defaultDPRequest.CounterValue),
		EUICCPublicKey: euiccSigner.PublicKey(),
		SequenceNumber: 6,
	})
	if err != nil {
		t.Fatalf("VerifyAndApplyResult(default DP) error = %v", err)
	}
	if !defaultDPResult.OK || defaultDPResult.Operation != OperationSetDefaultDPAddress {
		t.Fatalf("default DP result = %#v, want ok", defaultDPResult)
	}
	euiccState, err := store.GetEUICCState(ctx, storage.DefaultTenantID, eid)
	if err != nil {
		t.Fatalf("GetEUICCState(default DP) error = %v", err)
	}
	if euiccState.DefaultSMDPAddress != "smdp.example" {
		t.Fatalf("default SMDP address = %q, want smdp.example", euiccState.DefaultSMDPAddress)
	}
}

func TestNewPSMOErrorResultsMap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		pkg      protocolasn1.EuiccPackage
		result   protocolasn1.EuiccResultData
		wantCode ResultCode
	}{
		{name: "list profile info", pkg: ListProfileInfo(), result: profileListErrorResult(t, 11), wantCode: ResultProfileChangeOngoing},
		{name: "configure immediate enable", pkg: ConfigureImmediateEnable(false, nil, ""), result: integerResultData(t, 7, 1), wantCode: ResultInsufficientMemory},
		{name: "set fallback", pkg: SetFallbackAttribute([]byte{0x89, 0x10}), result: integerResultData(t, 13, 2), wantCode: ResultFallbackNotAllowed},
		{name: "unset fallback", pkg: UnsetFallbackAttribute(), result: integerResultData(t, 14, 2), wantCode: ResultNoFallbackAttribute},
		{name: "set default dp", pkg: SetDefaultDPAddress("smdp.example"), result: setDefaultDPResultData(t, 127), wantCode: ResultUndefinedError},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseOperationResult(tc.pkg, []protocolasn1.EuiccResultData{tc.result})
			if err != nil {
				t.Fatalf("ParseOperationResult() error = %v", err)
			}
			if result.OK || result.ResultCode != tc.wantCode {
				t.Fatalf("result = %#v, want code %s", result, tc.wantCode)
			}
		})
	}
}

type testSigner struct {
	key *ecdsa.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &testSigner{key: key}
}

func (s *testSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func (s *testSigner) PublicKey() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *testSigner) CertificateDER() []byte {
	return nil
}

func signPackage(
	t *testing.T,
	ctx context.Context,
	service *Service,
	eid string,
	eidValue []byte,
	transactionID []byte,
	pkg protocolasn1.EuiccPackage,
) *SignedRequest {
	t.Helper()
	request, err := service.Sign(ctx, SignInput{
		TenantID:         storage.DefaultTenantID,
		EID:              eid,
		EIDValue:         eidValue,
		EimTransactionID: transactionID,
		Package:          pkg,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return request
}

func signedResultDER(
	t *testing.T,
	signer *testSigner,
	request *SignedRequest,
	sequenceNumber int64,
	resultTag uint64,
	resultCode int64,
) []byte {
	t.Helper()
	return signedResultDERWithCounter(t, signer, request, sequenceNumber, resultTag, resultCode, request.CounterValue)
}

func signedResultDERWithCounter(
	t *testing.T,
	signer *testSigner,
	request *SignedRequest,
	sequenceNumber int64,
	resultTag uint64,
	resultCode int64,
	counter int64,
) []byte {
	t.Helper()
	resultData, err := protocolasn1.IntegerEuiccResult(resultTag, resultCode)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	return signedResultDataDER(t, signer, request, sequenceNumber, []protocolasn1.EuiccResultData{resultData}, counter)
}

func signedResultDataDER(
	t *testing.T,
	signer *testSigner,
	request *SignedRequest,
	sequenceNumber int64,
	results []protocolasn1.EuiccResultData,
	counter int64,
) []byte {
	t.Helper()
	data := protocolasn1.EuiccPackageResultDataSigned{
		EimID:            request.EimID,
		CounterValue:     counter,
		EimTransactionID: cloneBytes(request.EimTransactionID),
		SeqNumber:        sequenceNumber,
		Results:          results,
	}
	signature := signMarshaler(t, signer, &data)
	result := &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultOK,
		Signed: &protocolasn1.EuiccPackageResultSigned{
			Data:         data,
			EuiccSignEPR: signature,
		},
	}
	return encode(t, result)
}

func signedPackageErrorDER(t *testing.T, signer *testSigner, request *SignedRequest, code int64) []byte {
	t.Helper()
	data := protocolasn1.EuiccPackageErrorDataSigned{
		EimID:            request.EimID,
		CounterValue:     request.CounterValue,
		EimTransactionID: cloneBytes(request.EimTransactionID),
		ErrorCode:        protocolasn1.EuiccPackageErrorCode(code),
	}
	signature := signMarshaler(t, signer, &data)
	result := &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultErrorSigned,
		ErrorSigned: &protocolasn1.EuiccPackageErrorSigned{
			Data:         data,
			EuiccSignEPE: signature,
		},
	}
	return encode(t, result)
}

func unsignedPackageErrorDER(t *testing.T, request *SignedRequest, code int64) []byte {
	t.Helper()
	errorCode := protocolasn1.EuiccPackageUnsignedErrorCode(code)
	result := &protocolasn1.EuiccPackageResult{
		Kind: protocolasn1.EuiccPackageResultErrorUnsigned,
		ErrorUnsigned: &protocolasn1.EuiccPackageErrorUnsigned{
			EimID:            request.EimID,
			EimTransactionID: cloneBytes(request.EimTransactionID),
			ErrorCode:        &errorCode,
		},
	}
	return encode(t, result)
}

func signMarshaler(t *testing.T, signer *testSigner, value protocolasn1.Marshaler) []byte {
	t.Helper()
	payload := encode(t, value)
	signature := signRawBytes(t, signer, payload)
	return signature
}

func signRawBytes(t *testing.T, signer *testSigner, payload []byte) []byte {
	t.Helper()
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("sign raw bytes: %v", err)
	}
	return signature
}

func encode(t *testing.T, value protocolasn1.Marshaler) []byte {
	t.Helper()
	encoded, err := protocolasn1.Encode(value)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	return encoded
}

func verifyEIMSignature(t *testing.T, publicKey crypto.PublicKey, request *SignedRequest) {
	t.Helper()
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", publicKey)
	}
	digest := sha256.Sum256(request.SignatureInput)
	if !ecdsa.VerifyASN1(key, digest[:], request.Request.EimSignature) {
		t.Fatalf("eIM signature did not verify")
	}
}

func assertRequestRoundTrip(t *testing.T, der []byte) {
	t.Helper()
	var decoded protocolasn1.EuiccPackageRequest
	if err := protocolasn1.Decode(der, &decoded); err != nil {
		t.Fatalf("Decode(EuiccPackageRequest) error = %v", err)
	}
	reencoded, err := protocolasn1.Encode(&decoded)
	if err != nil {
		t.Fatalf("re-Encode(EuiccPackageRequest) error = %v", err)
	}
	if !bytes.Equal(reencoded, der) {
		t.Fatalf("request re-encode mismatch\n got %x\nwant %x", reencoded, der)
	}
}

func assertSignatureInputSuffix(t *testing.T, request *SignedRequest, suffix []byte) {
	t.Helper()
	if !bytes.Equal(request.SignatureInput, append(cloneBytes(request.SignedDER), suffix...)) {
		t.Fatalf("signature input = %x, want signed DER plus %x", request.SignatureInput, suffix)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return out
}

func registerWithState(t *testing.T, store storage.Store, eid string, states ...storage.ProfileState) {
	t.Helper()
	ctx := context.Background()
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	for _, state := range states {
		if err := store.SetProfileState(ctx, storage.DefaultTenantID, state); err != nil {
			t.Fatalf("SetProfileState() error = %v", err)
		}
	}
}

func testEIMConfiguration(t *testing.T, eimID string, counter int64, publicKey crypto.PublicKey) *protocolasn1.EimConfigurationData {
	t.Helper()
	config, err := NewEIMConfigurationDataFromPublicKey(eimID, eimID, counter, publicKey)
	if err != nil {
		t.Fatalf("NewEIMConfigurationDataFromPublicKey() error = %v", err)
	}
	return config
}

func assertAssociatedEIMToken(t *testing.T, store storage.Store, eid string, eimID string, want int64) {
	t.Helper()
	config := associatedEIMConfig(t, store, eid, eimID)
	if config.AssociationToken == nil || *config.AssociationToken != want {
		t.Fatalf("associated token = %#v, want %d", config.AssociationToken, want)
	}
}

func assertAssociatedEIMCounter(t *testing.T, store storage.Store, eid string, eimID string, want int64) {
	t.Helper()
	config := associatedEIMConfig(t, store, eid, eimID)
	if config.CounterValue == nil || *config.CounterValue != want {
		t.Fatalf("associated counter = %#v, want %d", config.CounterValue, want)
	}
}

func associatedEIMConfig(t *testing.T, store storage.Store, eid string, eimID string) protocolasn1.EimConfigurationData {
	t.Helper()
	associated, err := store.GetAssociatedEIM(context.Background(), storage.DefaultTenantID, eid, eimID)
	if err != nil {
		t.Fatalf("GetAssociatedEIM() error = %v", err)
	}
	var config protocolasn1.EimConfigurationData
	if err := protocolasn1.Decode(associated.ConfigPayload, &config); err != nil {
		t.Fatalf("Decode(EimConfigurationData) error = %v", err)
	}
	return config
}

func assertProfileEnabled(t *testing.T, store storage.Store, eid string, iccid []byte, want *bool) {
	t.Helper()
	iccidHex := hex.EncodeToString(iccid)
	profile, err := store.GetProfileState(context.Background(), storage.DefaultTenantID, eid, iccidHex)
	if err == nil {
		if want == nil {
			t.Fatalf("profile %s present with enabled=%v, want deleted", iccidHex, profile.IsEnabled)
		}
		if profile.IsEnabled != *want {
			t.Fatalf("profile %s enabled = %v, want %v", iccidHex, profile.IsEnabled, *want)
		}
		return
	}
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if want != nil {
		t.Fatalf("profile %s missing, want enabled=%v", iccidHex, *want)
	}
}

func assertProfileStateFull(t *testing.T, store storage.Store, eid string, iccid []byte, enabled bool, fallback bool, smdpAddress string) {
	t.Helper()
	iccidHex := hex.EncodeToString(iccid)
	profile, err := store.GetProfileState(context.Background(), storage.DefaultTenantID, eid, iccidHex)
	if err != nil {
		t.Fatalf("GetProfileState(%s) error = %v", iccidHex, err)
	}
	if profile.IsEnabled != enabled || profile.IsFallback != fallback || profile.SMDPAddress != smdpAddress {
		t.Fatalf("profile %s = %#v, want enabled=%v fallback=%v smdp=%q", iccidHex, profile, enabled, fallback, smdpAddress)
	}
}

func integerResultData(t *testing.T, tag uint64, value int64) protocolasn1.EuiccResultData {
	t.Helper()
	result, err := protocolasn1.IntegerEuiccResult(tag, value)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	return result
}

func profileListErrorResult(t *testing.T, value protocolasn1.ProfileInfoListError) protocolasn1.EuiccResultData {
	t.Helper()
	result, err := protocolasn1.ProfileInfoListEuiccResult(&protocolasn1.ProfileInfoListResponse{Error: &value})
	if err != nil {
		t.Fatalf("ProfileInfoListEuiccResult() error = %v", err)
	}
	return result
}

func setDefaultDPResultData(t *testing.T, value int64) protocolasn1.EuiccResultData {
	t.Helper()
	result, err := protocolasn1.SetDefaultDPAddressEuiccResult(&protocolasn1.SetDefaultDPAddressResponse{Result: value})
	if err != nil {
		t.Fatalf("SetDefaultDPAddressEuiccResult() error = %v", err)
	}
	return result
}

func mustTLV(t *testing.T, data []byte) *bertlv.TLV {
	t.Helper()
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary(%x) error = %v", data, err)
	}
	return tlv
}

func testEID(last byte) []byte {
	eid := make([]byte, 16)
	eid[15] = last
	return eid
}

func equalInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func boolPtr(value bool) *bool {
	return &value
}

func withLongFormLength(t *testing.T, tlv []byte) []byte {
	t.Helper()
	if len(tlv) < 2 || tlv[1]&0x80 != 0 {
		t.Fatalf("test TLV must use one-octet length: %x", tlv)
	}
	length := int(tlv[1])
	if len(tlv) != 2+length {
		t.Fatalf("test TLV length = %d, want %d", len(tlv), 2+length)
	}
	out := make([]byte, 0, len(tlv)+1)
	out = append(out, tlv[0], 0x81, byte(length))
	out = append(out, tlv[2:]...)
	return out
}

func wrapSignedResultTLV(signedData []byte, signature []byte) []byte {
	signatureTLV := makeTLV([]byte{0x5f, 0x37}, signature)
	signedResult := makeTLV([]byte{0x30}, append(cloneBytes(signedData), signatureTLV...))
	return makeTLV([]byte{0xbf, 0x51}, signedResult)
}

func makeTLV(tag []byte, value []byte) []byte {
	out := make([]byte, 0, len(tag)+len(value)+4)
	out = append(out, tag...)
	out = append(out, lengthBytes(len(value))...)
	out = append(out, value...)
	return out
}

func lengthBytes(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length <= 0xff {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length)}
}

func assertSignatureRejected(t *testing.T, publicKey crypto.PublicKey, payload []byte, signature []byte) {
	t.Helper()
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", publicKey)
	}
	digest := sha256.Sum256(payload)
	if ecdsa.VerifyASN1(key, digest[:], signature) {
		t.Fatalf("signature unexpectedly verifies against re-encoded canonical bytes")
	}
}

func ExampleEnable() {
	pkg := Enable([]byte{0x89, 0x10}, false)
	fmt.Println(pkg.Kind == protocolasn1.EuiccPackagePSMO)
	// Output: true
}
