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

	devices        map[deviceKey]memoryDevice
	profileStates  map[profileStateKey]storage.ProfileState
	associatedEIMs map[associatedEIMKey]storage.AssociatedEIM
	operations     map[int64]memoryOperation
	results        map[resultKey]storage.EUICCPackageResult
	eimConfigs     map[configKey]storage.EIMConfig
	notifications  []storedNotification

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

type profileStateKey struct {
	tenantID storage.TenantID
	eid      string
	iccid    string
}

type associatedEIMKey struct {
	tenantID storage.TenantID
	eid      string
	eimID    string
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
		profileStates:   make(map[profileStateKey]storage.ProfileState),
		associatedEIMs:  make(map[associatedEIMKey]storage.AssociatedEIM),
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

// GetProfileState reads one profile state.
func (s *Store) GetProfileState(ctx context.Context, tenantID storage.TenantID, eid string, iccid string) (storage.ProfileState, error) {
	if err := ctx.Err(); err != nil {
		return storage.ProfileState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.profileStates[newProfileStateKey(tenantID, eid, iccid)]
	if !ok {
		return storage.ProfileState{}, storage.ErrNotFound
	}
	return cloneProfileState(state), nil
}

// ListProfileStates reads all known profile states for one eUICC.
func (s *Store) ListProfileStates(ctx context.Context, tenantID storage.TenantID, eid string) ([]storage.ProfileState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceKey := newDeviceKey(tenantID, eid)
	if _, ok := s.devices[deviceKey]; !ok {
		return nil, storage.ErrNotFound
	}
	states := make([]storage.ProfileState, 0)
	for key, state := range s.profileStates {
		if key.tenantID == deviceKey.tenantID && key.eid == eid {
			states = append(states, cloneProfileState(state))
		}
	}
	sortProfileStates(states)
	return states, nil
}

// SetProfileState stores one profile state.
func (s *Store) SetProfileState(ctx context.Context, tenantID storage.TenantID, state storage.ProfileState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceKey := newDeviceKey(tenantID, state.EID)
	if _, ok := s.devices[deviceKey]; !ok {
		return storage.ErrNotFound
	}
	s.profileStates[newProfileStateKey(tenantID, state.EID, state.ICCID)] = cloneProfileState(state)
	return nil
}

// DeleteProfileState removes one profile state.
func (s *Store) DeleteProfileState(ctx context.Context, tenantID storage.TenantID, eid string, iccid string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceKey := newDeviceKey(tenantID, eid)
	if _, ok := s.devices[deviceKey]; !ok {
		return storage.ErrNotFound
	}
	key := newProfileStateKey(tenantID, eid, iccid)
	if _, ok := s.profileStates[key]; !ok {
		return storage.ErrNotFound
	}
	delete(s.profileStates, key)
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

// GetOperation reads one queued operation by id.
func (s *Store) GetOperation(ctx context.Context, tenantID storage.TenantID, operationID int64) (storage.Operation, error) {
	if err := ctx.Err(); err != nil {
		return storage.Operation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, ok := s.operations[operationID]
	if !ok || stored.tenantID != storage.NormalizeTenantID(tenantID) {
		return storage.Operation{}, storage.ErrNotFound
	}
	return cloneOperation(stored.operation), nil
}

// GetOperationBySequence reads one queued operation by tenant, EID, and sequence.
func (s *Store) GetOperationBySequence(ctx context.Context, tenantID storage.TenantID, eid string, sequenceNumber int64) (storage.Operation, error) {
	if err := ctx.Err(); err != nil {
		return storage.Operation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = storage.NormalizeTenantID(tenantID)
	for _, stored := range s.operations {
		operation := stored.operation
		if stored.tenantID == tenantID && operation.EID == eid && operation.SequenceNumber == sequenceNumber {
			return cloneOperation(operation), nil
		}
	}
	return storage.Operation{}, storage.ErrNotFound
}

// FetchPendingOperations returns pending operations in sequence order. Operations
// remain pending until their result is recorded so a dropped IPA exchange can
// safely fetch the same package again.
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
	for index := range pending {
		pending[index] = cloneOperation(pending[index])
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

// GetOperationResult reads the completion result for an operation by operation id.
func (s *Store) GetOperationResult(ctx context.Context, tenantID storage.TenantID, operationID int64) (storage.OperationResult, error) {
	if err := ctx.Err(); err != nil {
		return storage.OperationResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, ok := s.operations[operationID]
	if !ok || stored.tenantID != storage.NormalizeTenantID(tenantID) {
		return storage.OperationResult{}, storage.ErrNotFound
	}
	operation := stored.operation
	result, ok := s.results[resultKey{
		tenantID:       stored.tenantID,
		eid:            operation.EID,
		sequenceNumber: operation.SequenceNumber,
	}]
	if !ok {
		return storage.OperationResult{}, storage.ErrNotFound
	}
	return storage.OperationResult{
		OperationID:    operation.ID,
		EID:            result.EID,
		SequenceNumber: result.SequenceNumber,
		Status:         result.Status,
		Payload:        cloneBytes(result.Payload),
		CreatedAt:      operation.UpdatedAt,
	}, nil
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

// SetAssociatedEIM stores one Associated eIM state for one eUICC.
func (s *Store) SetAssociatedEIM(ctx context.Context, tenantID storage.TenantID, associated storage.AssociatedEIM) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := newAssociatedEIMKey(tenantID, associated.EID, associated.EIMID)
	if _, ok := s.devices[deviceKey{tenantID: key.tenantID, eid: key.eid}]; !ok {
		return storage.ErrNotFound
	}
	associated.EID = key.eid
	associated.EIMID = key.eimID
	s.associatedEIMs[key] = cloneAssociatedEIM(associated)
	return nil
}

// DeleteAssociatedEIM removes one Associated eIM state for one eUICC.
func (s *Store) DeleteAssociatedEIM(ctx context.Context, tenantID storage.TenantID, eid string, eimID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := newAssociatedEIMKey(tenantID, eid, eimID)
	if _, ok := s.devices[deviceKey{tenantID: key.tenantID, eid: key.eid}]; !ok {
		return storage.ErrNotFound
	}
	if _, ok := s.associatedEIMs[key]; !ok {
		return storage.ErrNotFound
	}
	delete(s.associatedEIMs, key)
	return nil
}

// GetAssociatedEIM reads one Associated eIM state for one eUICC.
func (s *Store) GetAssociatedEIM(ctx context.Context, tenantID storage.TenantID, eid string, eimID string) (storage.AssociatedEIM, error) {
	if err := ctx.Err(); err != nil {
		return storage.AssociatedEIM{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	associated, ok := s.associatedEIMs[newAssociatedEIMKey(tenantID, eid, eimID)]
	if !ok {
		return storage.AssociatedEIM{}, storage.ErrNotFound
	}
	return cloneAssociatedEIM(associated), nil
}

// ListAssociatedEIMs reads all Associated eIM states for one eUICC.
func (s *Store) ListAssociatedEIMs(ctx context.Context, tenantID storage.TenantID, eid string) ([]storage.AssociatedEIM, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceKey := newDeviceKey(tenantID, eid)
	if _, ok := s.devices[deviceKey]; !ok {
		return nil, storage.ErrNotFound
	}
	items := make([]storage.AssociatedEIM, 0)
	for key, associated := range s.associatedEIMs {
		if key.tenantID == deviceKey.tenantID && key.eid == eid {
			items = append(items, cloneAssociatedEIM(associated))
		}
	}
	sortAssociatedEIMs(items)
	return items, nil
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

func newProfileStateKey(tenantID storage.TenantID, eid string, iccid string) profileStateKey {
	return profileStateKey{tenantID: storage.NormalizeTenantID(tenantID), eid: eid, iccid: iccid}
}

func newAssociatedEIMKey(tenantID storage.TenantID, eid string, eimID string) associatedEIMKey {
	return associatedEIMKey{tenantID: storage.NormalizeTenantID(tenantID), eid: eid, eimID: eimID}
}

func sortOperations(operations []storage.Operation) {
	for i := 1; i < len(operations); i++ {
		for j := i; j > 0 && operations[j-1].SequenceNumber > operations[j].SequenceNumber; j-- {
			operations[j-1], operations[j] = operations[j], operations[j-1]
		}
	}
}

func sortProfileStates(states []storage.ProfileState) {
	for i := 1; i < len(states); i++ {
		for j := i; j > 0 && states[j-1].ICCID > states[j].ICCID; j-- {
			states[j-1], states[j] = states[j], states[j-1]
		}
	}
}

func sortAssociatedEIMs(items []storage.AssociatedEIM) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j-1].EIMID > items[j].EIMID; j-- {
			items[j-1], items[j] = items[j], items[j-1]
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
	return state
}

func cloneOperation(operation storage.Operation) storage.Operation {
	operation.Payload = cloneBytes(operation.Payload)
	return operation
}

func cloneEIMConfig(config storage.EIMConfig) storage.EIMConfig {
	return storage.EIMConfig{EIMID: config.EIMID, Data: cloneBytes(config.Data)}
}

func cloneAssociatedEIM(associated storage.AssociatedEIM) storage.AssociatedEIM {
	associated.ConfigPayload = cloneBytes(associated.ConfigPayload)
	if associated.EIMIDType != nil {
		value := *associated.EIMIDType
		associated.EIMIDType = &value
	}
	return associated
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
