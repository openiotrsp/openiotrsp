// Package memory provides an in-memory storage.Store implementation for fast
// protocol tests.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/openiotrsp/openiotrsp/storage"
)

// Store is an in-memory storage.Store implementation safe for concurrent tests.
type Store struct {
	mu sync.Mutex

	devices       map[deviceKey]memoryDevice
	profileStates map[deviceKey]storage.ProfileState
	operations    map[int64]memoryOperation
	results       map[resultKey]storage.EUICCPackageResult
	eimConfigs    map[configKey]storage.EIMConfig
	notifications []storedNotification

	nextOperationID int64
}

type memoryDevice struct {
	nextSequence            int64
	nextEUICCPackageCounter int64
}

type memoryOperation struct {
	tenantID  storage.TenantID
	operation storage.Operation
}

type deviceKey struct {
	tenantID storage.TenantID
	eid      string
}

type resultKey struct {
	tenantID       storage.TenantID
	eid            string
	sequenceNumber int64
}

type configKey struct {
	tenantID storage.TenantID
	eimID    string
}

type storedNotification struct {
	tenantID     storage.TenantID
	notification storage.Notification
}

// New returns an empty in-memory Store.
func New() *Store {
	return &Store{
		devices:         make(map[deviceKey]memoryDevice),
		profileStates:   make(map[deviceKey]storage.ProfileState),
		operations:      make(map[int64]memoryOperation),
		results:         make(map[resultKey]storage.EUICCPackageResult),
		eimConfigs:      make(map[configKey]storage.EIMConfig),
		nextOperationID: 1,
	}
}

// RegisterDevice registers or refreshes a device by EID.
func (s *Store) RegisterDevice(ctx context.Context, tenantID storage.TenantID, device storage.Device) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := newDeviceKey(tenantID, device.EID)
	if _, ok := s.devices[key]; ok {
		return nil
	}
	s.devices[key] = memoryDevice{nextSequence: 1, nextEUICCPackageCounter: 1}
	return nil
}

// GetProfileState reads one device's profile state.
func (s *Store) GetProfileState(ctx context.Context, tenantID storage.TenantID, eid string) (storage.ProfileState, error) {
	if err := ctx.Err(); err != nil {
		return storage.ProfileState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.profileStates[newDeviceKey(tenantID, eid)]
	if !ok {
		return storage.ProfileState{}, storage.ErrNotFound
	}
	return cloneProfileState(state), nil
}

// SetProfileState stores one device's profile state.
func (s *Store) SetProfileState(ctx context.Context, tenantID storage.TenantID, state storage.ProfileState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := newDeviceKey(tenantID, state.EID)
	if _, ok := s.devices[key]; !ok {
		return storage.ErrNotFound
	}
	s.profileStates[key] = cloneProfileState(state)
	return nil
}

// NextEUICCPackageCounter returns the next eUICC package counter and persists
// the increment atomically for this tenant and EID.
func (s *Store) NextEUICCPackageCounter(ctx context.Context, tenantID storage.TenantID, eid string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := newDeviceKey(tenantID, eid)
	device, ok := s.devices[key]
	if !ok {
		return 0, storage.ErrNotFound
	}
	counter := device.nextEUICCPackageCounter
	device.nextEUICCPackageCounter++
	s.devices[key] = device
	return counter, nil
}

// EnqueueOperation appends pending work for a device.
func (s *Store) EnqueueOperation(ctx context.Context, tenantID storage.TenantID, request storage.OperationRequest) (storage.Operation, error) {
	if err := ctx.Err(); err != nil {
		return storage.Operation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := newDeviceKey(tenantID, request.EID)
	device, ok := s.devices[key]
	if !ok {
		return storage.Operation{}, storage.ErrNotFound
	}

	now := time.Now().UTC()
	operation := storage.Operation{
		ID:             s.nextOperationID,
		EID:            request.EID,
		SequenceNumber: device.nextSequence,
		Kind:           request.Kind,
		Payload:        cloneBytes(request.Payload),
		Status:         storage.OperationPending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.nextOperationID++
	device.nextSequence++
	s.devices[key] = device
	s.operations[operation.ID] = memoryOperation{tenantID: key.tenantID, operation: operation}
	return cloneOperation(operation), nil
}

// FetchPendingOperations returns pending operations in sequence order and marks
// them in-flight.
func (s *Store) FetchPendingOperations(ctx context.Context, tenantID storage.TenantID, eid string, limit int) ([]storage.Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = storage.NormalizeTenantID(tenantID)
	pending := make([]storage.Operation, 0)
	for _, stored := range s.operations {
		operation := stored.operation
		if stored.tenantID == tenantID && operation.EID == eid && operation.Status == storage.OperationPending {
			pending = append(pending, operation)
		}
	}
	sortOperations(pending)
	if len(pending) > limit {
		pending = pending[:limit]
	}

	now := time.Now().UTC()
	for index := range pending {
		operation := pending[index]
		operation.Status = storage.OperationInFlight
		operation.UpdatedAt = now
		s.operations[operation.ID] = memoryOperation{tenantID: tenantID, operation: operation}
		pending[index] = cloneOperation(operation)
	}
	return pending, nil
}

// RecordEUICCPackageResult stores a result and marks the matching operation done
// or failed.
func (s *Store) RecordEUICCPackageResult(ctx context.Context, tenantID storage.TenantID, result storage.EUICCPackageResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = storage.NormalizeTenantID(tenantID)
	if result.OperationID != 0 {
		stored, ok := s.operations[result.OperationID]
		if !ok || stored.tenantID != tenantID {
			return storage.ErrNotFound
		}
		result.EID = stored.operation.EID
		result.SequenceNumber = stored.operation.SequenceNumber
	}
	key := deviceKey{tenantID: tenantID, eid: result.EID}
	if _, ok := s.devices[key]; !ok {
		return storage.ErrNotFound
	}

	result.Status = normalizeResultStatus(result.Status)
	result.Payload = cloneBytes(result.Payload)
	s.results[resultKey{
		tenantID:       tenantID,
		eid:            result.EID,
		sequenceNumber: result.SequenceNumber,
	}] = result

	for id, stored := range s.operations {
		if stored.tenantID != tenantID {
			continue
		}
		operation := stored.operation
		if result.OperationID != 0 && operation.ID != result.OperationID {
			continue
		}
		if result.OperationID == 0 && (operation.EID != result.EID || operation.SequenceNumber != result.SequenceNumber) {
			continue
		}
		operation.Status = result.Status
		operation.UpdatedAt = time.Now().UTC()
		stored.operation = operation
		s.operations[id] = stored
		return nil
	}
	return nil
}

// StoreEIMConfig stores an encoded eIM configuration.
func (s *Store) StoreEIMConfig(ctx context.Context, tenantID storage.TenantID, config storage.EIMConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.eimConfigs[configKey{tenantID: storage.NormalizeTenantID(tenantID), eimID: config.EIMID}] = cloneEIMConfig(config)
	return nil
}

// ReadEIMConfig reads an encoded eIM configuration.
func (s *Store) ReadEIMConfig(ctx context.Context, tenantID storage.TenantID, eimID string) (storage.EIMConfig, error) {
	if err := ctx.Err(); err != nil {
		return storage.EIMConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	config, ok := s.eimConfigs[configKey{tenantID: storage.NormalizeTenantID(tenantID), eimID: eimID}]
	if !ok {
		return storage.EIMConfig{}, storage.ErrNotFound
	}
	return cloneEIMConfig(config), nil
}

// StoreNotification stores an encoded device notification.
func (s *Store) StoreNotification(ctx context.Context, tenantID storage.TenantID, notification storage.Notification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = storage.NormalizeTenantID(tenantID)
	if _, ok := s.devices[deviceKey{tenantID: tenantID, eid: notification.EID}]; !ok {
		return storage.ErrNotFound
	}
	s.notifications = append(s.notifications, storedNotification{
		tenantID: tenantID,
		notification: storage.Notification{
			EID:     notification.EID,
			Kind:    notification.Kind,
			Payload: cloneBytes(notification.Payload),
		},
	})
	return nil
}

func newDeviceKey(tenantID storage.TenantID, eid string) deviceKey {
	return deviceKey{tenantID: storage.NormalizeTenantID(tenantID), eid: eid}
}

func sortOperations(operations []storage.Operation) {
	for i := 1; i < len(operations); i++ {
		for j := i; j > 0 && operations[j-1].SequenceNumber > operations[j].SequenceNumber; j-- {
			operations[j-1], operations[j] = operations[j], operations[j-1]
		}
	}
}

func normalizeResultStatus(status storage.OperationStatus) storage.OperationStatus {
	if status == storage.OperationFailed {
		return storage.OperationFailed
	}
	return storage.OperationDone
}

func cloneProfileState(state storage.ProfileState) storage.ProfileState {
	return storage.ProfileState{EID: state.EID, Data: cloneBytes(state.Data)}
}

func cloneOperation(operation storage.Operation) storage.Operation {
	operation.Payload = cloneBytes(operation.Payload)
	return operation
}

func cloneEIMConfig(config storage.EIMConfig) storage.EIMConfig {
	return storage.EIMConfig{EIMID: config.EIMID, Data: cloneBytes(config.Data)}
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copied := make([]byte, len(value))
	copy(copied, value)
	return copied
}

var _ storage.Store = (*Store)(nil)
