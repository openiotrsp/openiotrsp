// Package storetest contains conformance tests for storage.Store implementations.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

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

	if _, err := store.GetProfileState(ctx, tenantID, eid); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetProfileState() error = %v, want %v", err, storage.ErrNotFound)
	}
	if _, err := store.ReadEIMConfig(ctx, tenantID, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("ReadEIMConfig() error = %v, want %v", err, storage.ErrNotFound)
	}
	if err := store.RegisterDevice(ctx, tenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	statePayload := []byte(`{"profiles":[{"iccid":"891"}]}`)
	if err := store.SetProfileState(ctx, tenantID, storage.ProfileState{EID: eid, Data: statePayload}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}
	statePayload[0] = '!'
	gotState, err := store.GetProfileState(ctx, tenantID, eid)
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	assertBytes(t, "profile state", gotState.Data, []byte(`{"profiles":[{"iccid":"891"}]}`))

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
	if err := store.RecordEUICCPackageResult(ctx, tenantID, storage.EUICCPackageResult{
		OperationID:    operation.ID,
		SequenceNumber: operation.SequenceNumber,
		Status:         storage.OperationDone,
		Payload:        []byte("result"),
	}); err != nil {
		t.Fatalf("RecordEUICCPackageResult() error = %v", err)
	}
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
	if err := store.SetProfileState(ctx, tenantA, storage.ProfileState{EID: eid, Data: []byte("tenant-a")}); err != nil {
		t.Fatalf("SetProfileState(tenantA) error = %v", err)
	}
	if err := store.SetProfileState(ctx, tenantB, storage.ProfileState{EID: eid, Data: []byte("tenant-b")}); err != nil {
		t.Fatalf("SetProfileState(tenantB) error = %v", err)
	}

	gotA, err := store.GetProfileState(ctx, tenantA, eid)
	if err != nil {
		t.Fatalf("GetProfileState(tenantA) error = %v", err)
	}
	gotB, err := store.GetProfileState(ctx, tenantB, eid)
	if err != nil {
		t.Fatalf("GetProfileState(tenantB) error = %v", err)
	}
	assertBytes(t, "tenant A state", gotA.Data, []byte("tenant-a"))
	assertBytes(t, "tenant B state", gotB.Data, []byte("tenant-b"))

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
		if operation.Status != storage.OperationInFlight {
			t.Fatalf("operation %d status = %q, want %q", index, operation.Status, storage.OperationInFlight)
		}
	}

	secondPoll, err := store.FetchPendingOperations(ctx, tenantID, eid, 10)
	if err != nil {
		t.Fatalf("FetchPendingOperations(second) error = %v", err)
	}
	if len(secondPoll) != 0 {
		t.Fatalf("second poll returned %d operations, want 0", len(secondPoll))
	}
}

func testConcurrentQueueSafety(t *testing.T, store storage.Store) {
	ctx := context.Background()
	tenantID := storage.DefaultTenantID
	eid := uniqueEID(t, "concurrent")
	const operationCount = 64
	const fetcherCount = 8

	if err := store.RegisterDevice(ctx, tenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	enqueuesDone := make(chan struct{})
	errs := make(chan error, operationCount+fetcherCount)
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

	var fetchedMu sync.Mutex
	fetched := make(map[int64]storage.Operation)
	var fetchWG sync.WaitGroup
	fetchWG.Add(fetcherCount)
	for range fetcherCount {
		go func() {
			defer fetchWG.Done()
			for {
				operations, err := store.FetchPendingOperations(ctx, tenantID, eid, 3)
				if err != nil {
					errs <- fmt.Errorf("fetch: %w", err)
					return
				}
				if len(operations) == 0 {
					select {
					case <-enqueuesDone:
						return
					default:
						time.Sleep(time.Millisecond)
						continue
					}
				}
				fetchedMu.Lock()
				for _, operation := range operations {
					if _, exists := fetched[operation.ID]; exists {
						errs <- fmt.Errorf("duplicate operation id %d", operation.ID)
						continue
					}
					fetched[operation.ID] = operation
				}
				fetchedMu.Unlock()
			}
		}()
	}
	fetchWG.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(fetched) != operationCount {
		t.Fatalf("fetched %d operations, want %d", len(fetched), operationCount)
	}

	seenSequences := make(map[int64]bool, operationCount)
	for _, operation := range fetched {
		if operation.Status != storage.OperationInFlight {
			t.Fatalf("operation %d status = %q, want %q", operation.ID, operation.Status, storage.OperationInFlight)
		}
		if operation.SequenceNumber < 1 || operation.SequenceNumber > operationCount {
			t.Fatalf("operation %d sequence = %d, outside 1..%d", operation.ID, operation.SequenceNumber, operationCount)
		}
		if seenSequences[operation.SequenceNumber] {
			t.Fatalf("duplicate sequence %d", operation.SequenceNumber)
		}
		seenSequences[operation.SequenceNumber] = true
	}

	secondPoll, err := store.FetchPendingOperations(ctx, tenantID, eid, operationCount)
	if err != nil {
		t.Fatalf("FetchPendingOperations(after concurrent fetch) error = %v", err)
	}
	if len(secondPoll) != 0 {
		t.Fatalf("second poll returned %d operations, want 0", len(secondPoll))
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
