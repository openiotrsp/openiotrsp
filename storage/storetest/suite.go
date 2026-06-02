// Package storetest contains conformance tests for storage.Store implementations.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/openiotrsp/openiotrsp/storage"
)

// Factory creates a clean Store for one conformance subtest.
type Factory func(t testing.TB) storage.Store

// Run exercises the shared storage.Store contract.
func Run(t *testing.T, factory Factory) {
	t.Helper()

	tests := []struct {
		name string
		run  func(t *testing.T, store storage.Store)
	}{
		{"device profile config result notification", testRecords},
		{"tenant isolation", testTenantIsolation},
		{"eUICC package counter monotonicity", testEUICCPackageCounterMonotonicity},
		{"operation queue polling", testOperationQueuePolling},
		{"concurrent queue safety", testConcurrentQueueSafety},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			test.run(t, factory(t))
		})
	}
}

func testRecords(t *testing.T, store storage.Store) {
	ctx := context.Background()
	tenantID := storage.DefaultTenantID
	eid := uniqueEID(t, "records")

	if _, err := store.GetProfileState(ctx, tenantID, eid, "891"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetProfileState() error = %v, want %v", err, storage.ErrNotFound)
	}
	if _, err := store.ReadEIMConfig(ctx, tenantID, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("ReadEIMConfig() error = %v, want %v", err, storage.ErrNotFound)
	}
	if err := store.RegisterDevice(ctx, tenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	if err := store.SetProfileState(ctx, tenantID, storage.ProfileState{
		EID:         eid,
		ICCID:       "891",
		IsEnabled:   true,
		SMDPAddress: "smdp.example",
	}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}
	gotState, err := store.GetProfileState(ctx, tenantID, eid, "891")
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if gotState.ICCID != "891" || !gotState.IsEnabled || gotState.SMDPAddress != "smdp.example" {
		t.Fatalf("profile state = %#v, want enabled 891 with smdp.example", gotState)
	}
	gotStates, err := store.ListProfileStates(ctx, tenantID, eid)
	if err != nil {
		t.Fatalf("ListProfileStates() error = %v", err)
	}
	if len(gotStates) != 1 || gotStates[0].ICCID != "891" {
		t.Fatalf("ListProfileStates() = %#v, want one profile 891", gotStates)
	}
	if err := store.DeleteProfileState(ctx, tenantID, eid, "891"); err != nil {
		t.Fatalf("DeleteProfileState() error = %v", err)
	}
	if _, err := store.GetProfileState(ctx, tenantID, eid, "891"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetProfileState(deleted) error = %v, want %v", err, storage.ErrNotFound)
	}

	configPayload := []byte("encoded-eim-config")
	if err := store.StoreEIMConfig(ctx, tenantID, storage.EIMConfig{EIMID: "eim.example", Data: configPayload}); err != nil {
		t.Fatalf("StoreEIMConfig() error = %v", err)
	}
	configPayload[0] = '!'
	gotConfig, err := store.ReadEIMConfig(ctx, tenantID, "eim.example")
	if err != nil {
		t.Fatalf("ReadEIMConfig() error = %v", err)
	}
	assertBytes(t, "eIM config", gotConfig.Data, []byte("encoded-eim-config"))

	eimType := int64(2)
	associatedPayload := []byte("encoded-associated-eim")
	if err := store.SetAssociatedEIM(ctx, tenantID, storage.AssociatedEIM{
		EID:           eid,
		EIMID:         "assoc.eim",
		EIMIDType:     &eimType,
		ConfigPayload: associatedPayload,
	}); err != nil {
		t.Fatalf("SetAssociatedEIM() error = %v", err)
	}
	associatedPayload[0] = '!'
	gotAssociated, err := store.GetAssociatedEIM(ctx, tenantID, eid, "assoc.eim")
	if err != nil {
		t.Fatalf("GetAssociatedEIM() error = %v", err)
	}
	if gotAssociated.EID != eid || gotAssociated.EIMID != "assoc.eim" || gotAssociated.EIMIDType == nil || *gotAssociated.EIMIDType != eimType {
		t.Fatalf("associated eIM = %#v, want assoc.eim type %d", gotAssociated, eimType)
	}
	assertBytes(t, "associated eIM payload", gotAssociated.ConfigPayload, []byte("encoded-associated-eim"))
	associatedList, err := store.ListAssociatedEIMs(ctx, tenantID, eid)
	if err != nil {
		t.Fatalf("ListAssociatedEIMs() error = %v", err)
	}
	if len(associatedList) != 1 || associatedList[0].EIMID != "assoc.eim" {
		t.Fatalf("ListAssociatedEIMs() = %#v, want assoc.eim", associatedList)
	}
	if err := store.DeleteAssociatedEIM(ctx, tenantID, eid, "assoc.eim"); err != nil {
		t.Fatalf("DeleteAssociatedEIM() error = %v", err)
	}
	if _, err := store.GetAssociatedEIM(ctx, tenantID, eid, "assoc.eim"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetAssociatedEIM(deleted) error = %v, want %v", err, storage.ErrNotFound)
	}

	if err := store.StoreNotification(ctx, tenantID, storage.Notification{
		EID:     eid,
		Kind:    "state-change",
		Payload: []byte("notification"),
	}); err != nil {
		t.Fatalf("StoreNotification() error = %v", err)
	}

	operation, err := store.EnqueueOperation(ctx, tenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationEuiccPackage,
		Payload: []byte("package"),
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}
	gotOperation, err := store.GetOperation(ctx, tenantID, operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if gotOperation.ID != operation.ID || gotOperation.SequenceNumber != operation.SequenceNumber {
		t.Fatalf("GetOperation() = %#v, want id %d sequence %d", gotOperation, operation.ID, operation.SequenceNumber)
	}
	gotBySequence, err := store.GetOperationBySequence(ctx, tenantID, eid, operation.SequenceNumber)
	if err != nil {
		t.Fatalf("GetOperationBySequence() error = %v", err)
	}
	if gotBySequence.ID != operation.ID {
		t.Fatalf("GetOperationBySequence() id = %d, want %d", gotBySequence.ID, operation.ID)
	}
	if _, err := store.GetOperationResult(ctx, tenantID, operation.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetOperationResult(missing) error = %v, want %v", err, storage.ErrNotFound)
	}
	if err := store.RecordEUICCPackageResult(ctx, tenantID, storage.EUICCPackageResult{
		OperationID:    operation.ID,
		SequenceNumber: operation.SequenceNumber,
		Status:         storage.OperationDone,
		Payload:        []byte("result"),
	}); err != nil {
		t.Fatalf("RecordEUICCPackageResult() error = %v", err)
	}
	doneOperation, err := store.GetOperation(ctx, tenantID, operation.ID)
	if err != nil {
		t.Fatalf("GetOperation(done) error = %v", err)
	}
	if doneOperation.Status != storage.OperationDone {
		t.Fatalf("operation status = %q, want %q", doneOperation.Status, storage.OperationDone)
	}
	result, err := store.GetOperationResult(ctx, tenantID, operation.ID)
	if err != nil {
		t.Fatalf("GetOperationResult() error = %v", err)
	}
	if result.OperationID != operation.ID || result.SequenceNumber != operation.SequenceNumber || result.Status != storage.OperationDone {
		t.Fatalf("operation result = %#v, want operation %d sequence %d done", result, operation.ID, operation.SequenceNumber)
	}
	assertBytes(t, "operation result payload", result.Payload, []byte("result"))
}

func testTenantIsolation(t *testing.T, store storage.Store) {
	ctx := context.Background()
	eid := uniqueEID(t, "tenant")
	tenantA := storage.DefaultTenantID
	tenantB := storage.TenantID("tenant-b")

	for _, tenantID := range []storage.TenantID{tenantA, tenantB} {
		if err := store.RegisterDevice(ctx, tenantID, storage.Device{EID: eid}); err != nil {
			t.Fatalf("RegisterDevice(%s) error = %v", tenantID, err)
		}
	}
	if err := store.SetProfileState(ctx, tenantA, storage.ProfileState{EID: eid, ICCID: "891", IsEnabled: true}); err != nil {
		t.Fatalf("SetProfileState(tenantA) error = %v", err)
	}
	if err := store.SetProfileState(ctx, tenantB, storage.ProfileState{EID: eid, ICCID: "891", IsEnabled: false}); err != nil {
		t.Fatalf("SetProfileState(tenantB) error = %v", err)
	}

	gotA, err := store.GetProfileState(ctx, tenantA, eid, "891")
	if err != nil {
		t.Fatalf("GetProfileState(tenantA) error = %v", err)
	}
	gotB, err := store.GetProfileState(ctx, tenantB, eid, "891")
	if err != nil {
		t.Fatalf("GetProfileState(tenantB) error = %v", err)
	}
	if !gotA.IsEnabled {
		t.Fatalf("tenant A profile enabled = false, want true")
	}
	if gotB.IsEnabled {
		t.Fatalf("tenant B profile enabled = true, want false")
	}

	if _, err := store.EnqueueOperation(ctx, tenantA, storage.OperationRequest{EID: eid, Kind: storage.OperationEuiccPackage, Payload: []byte("a")}); err != nil {
		t.Fatalf("EnqueueOperation(tenantA) error = %v", err)
	}
	if _, err := store.EnqueueOperation(ctx, tenantB, storage.OperationRequest{EID: eid, Kind: storage.OperationEuiccPackage, Payload: []byte("b")}); err != nil {
		t.Fatalf("EnqueueOperation(tenantB) error = %v", err)
	}
	pendingA, err := store.FetchPendingOperations(ctx, tenantA, eid, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations(tenantA) error = %v", err)
	}
	if len(pendingA) != 1 || string(pendingA[0].Payload) != "a" {
		t.Fatalf("tenant A pending = %#v, want one payload a", pendingA)
	}
	pendingB, err := store.FetchPendingOperations(ctx, tenantB, eid, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations(tenantB) error = %v", err)
	}
	if len(pendingB) != 1 || string(pendingB[0].Payload) != "b" {
		t.Fatalf("tenant B pending = %#v, want one payload b", pendingB)
	}
}

func testEUICCPackageCounterMonotonicity(t *testing.T, store storage.Store) {
	ctx := context.Background()
	tenantID := storage.DefaultTenantID
	eid := uniqueEID(t, "counter")
	otherEID := eid + "-other"

	if _, err := store.NextEUICCPackageCounter(ctx, tenantID, eid); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("NextEUICCPackageCounter(missing) error = %v, want %v", err, storage.ErrNotFound)
	}
	for _, deviceEID := range []string{eid, otherEID} {
		if err := store.RegisterDevice(ctx, tenantID, storage.Device{EID: deviceEID}); err != nil {
			t.Fatalf("RegisterDevice(%s) error = %v", deviceEID, err)
		}
	}

	for want := int64(1); want <= 3; want++ {
		got, err := store.NextEUICCPackageCounter(ctx, tenantID, eid)
		if err != nil {
			t.Fatalf("NextEUICCPackageCounter(%d) error = %v", want, err)
		}
		if got != want {
			t.Fatalf("counter = %d, want %d", got, want)
		}
	}
	other, err := store.NextEUICCPackageCounter(ctx, tenantID, otherEID)
	if err != nil {
		t.Fatalf("NextEUICCPackageCounter(other) error = %v", err)
	}
	if other != 1 {
		t.Fatalf("other EID counter = %d, want 1", other)
	}
}

func testOperationQueuePolling(t *testing.T, store storage.Store) {
	ctx := context.Background()
	tenantID := storage.DefaultTenantID
	eid := uniqueEID(t, "queue")

	if err := store.RegisterDevice(ctx, tenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	for index := range 3 {
		operation, err := store.EnqueueOperation(ctx, tenantID, storage.OperationRequest{
			EID:     eid,
			Kind:    storage.OperationEuiccPackage,
			Payload: []byte(fmt.Sprintf("payload-%d", index+1)),
		})
		if err != nil {
			t.Fatalf("EnqueueOperation(%d) error = %v", index, err)
		}
		wantSequence := int64(index + 1)
		if operation.SequenceNumber != wantSequence {
			t.Fatalf("sequence = %d, want %d", operation.SequenceNumber, wantSequence)
		}
		if operation.Status != storage.OperationPending {
			t.Fatalf("status = %q, want %q", operation.Status, storage.OperationPending)
		}
	}

	firstPoll, err := store.FetchPendingOperations(ctx, tenantID, eid, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations(first) error = %v", err)
	}
	if len(firstPoll) != 3 {
		t.Fatalf("first poll returned %d operations, want 3", len(firstPoll))
	}
	for index, operation := range firstPoll {
		wantSequence := int64(index + 1)
		if operation.SequenceNumber != wantSequence {
			t.Fatalf("operation %d sequence = %d, want %d", index, operation.SequenceNumber, wantSequence)
		}
		if operation.Status != storage.OperationPending {
			t.Fatalf("operation %d status = %q, want %q", index, operation.Status, storage.OperationPending)
		}
	}

	secondPoll, err := store.FetchPendingOperations(ctx, tenantID, eid, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations(second) error = %v", err)
	}
	if len(secondPoll) != 3 {
		t.Fatalf("second poll returned %d operations, want 3 redelivered operations", len(secondPoll))
	}
	for index, operation := range secondPoll {
		wantSequence := int64(index + 1)
		if operation.SequenceNumber != wantSequence {
			t.Fatalf("redelivered operation %d sequence = %d, want %d", index, operation.SequenceNumber, wantSequence)
		}
	}
	for _, operation := range secondPoll {
		if err := store.RecordEUICCPackageResult(ctx, tenantID, storage.EUICCPackageResult{
			EID:            eid,
			SequenceNumber: operation.SequenceNumber,
			Status:         storage.OperationDone,
			Payload:        []byte("result"),
		}); err != nil {
			t.Fatalf("RecordEUICCPackageResult(%d) error = %v", operation.SequenceNumber, err)
		}
	}
	thirdPoll, err := store.FetchPendingOperations(ctx, tenantID, eid, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations(third) error = %v", err)
	}
	if len(thirdPoll) != 0 {
		t.Fatalf("third poll returned %d operations, want 0 after results", len(thirdPoll))
	}
}

func testConcurrentQueueSafety(t *testing.T, store storage.Store) {
	ctx := context.Background()
	tenantID := storage.DefaultTenantID
	eid := uniqueEID(t, "concurrent")
	const operationCount = 64

	if err := store.RegisterDevice(ctx, tenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	enqueuesDone := make(chan struct{})
	errs := make(chan error, operationCount)
	var enqueueWG sync.WaitGroup
	enqueueWG.Add(operationCount)
	for index := range operationCount {
		index := index
		go func() {
			defer enqueueWG.Done()
			_, err := store.EnqueueOperation(ctx, tenantID, storage.OperationRequest{
				EID:     eid,
				Kind:    storage.OperationEuiccPackage,
				Payload: []byte(fmt.Sprintf("op-%d", index)),
			})
			if err != nil {
				errs <- fmt.Errorf("enqueue %d: %w", index, err)
			}
		}()
	}
	go func() {
		enqueueWG.Wait()
		close(enqueuesDone)
	}()

	<-enqueuesDone
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	fetched, err := store.FetchPendingOperations(ctx, tenantID, eid, operationCount)
	if err != nil {
		t.Fatalf("FetchPendingOperations(after concurrent enqueue) error = %v", err)
	}
	if len(fetched) != operationCount {
		t.Fatalf("fetched %d operations, want %d", len(fetched), operationCount)
	}

	seenSequences := make(map[int64]bool, operationCount)
	for _, operation := range fetched {
		if operation.Status != storage.OperationPending {
			t.Fatalf("operation %d status = %q, want %q", operation.ID, operation.Status, storage.OperationPending)
		}
		if operation.SequenceNumber < 1 || operation.SequenceNumber > operationCount {
			t.Fatalf("operation %d sequence = %d, outside 1..%d", operation.ID, operation.SequenceNumber, operationCount)
		}
		if seenSequences[operation.SequenceNumber] {
			t.Fatalf("duplicate sequence %d", operation.SequenceNumber)
		}
		seenSequences[operation.SequenceNumber] = true
	}

}

func uniqueEID(t testing.TB, suffix string) string {
	t.Helper()
	return fmt.Sprintf("eid-%s-%s", sanitizeName(t.Name()), suffix)
}

func sanitizeName(name string) string {
	out := []byte(name)
	for index, value := range out {
		if value == '/' || value == ' ' {
			out[index] = '-'
		}
	}
	return string(out)
}

func assertBytes(t testing.TB, label string, got []byte, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", label, got, want)
	}
}
