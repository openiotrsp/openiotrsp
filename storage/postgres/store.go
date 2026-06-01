// Package postgres provides a pgx-backed storage.Store implementation.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openiotrsp/openiotrsp/storage"
)

// Store is a Postgres-backed storage.Store.
type Store struct {
	pool *pgxpool.Pool
}

// Open creates a Store backed by a new pgx pool.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres storage: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres storage: ping: %w", err)
	}
	return New(pool), nil
}

// New wraps an existing pgx pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Close closes the underlying pgx pool.
func (s *Store) Close() {
	s.pool.Close()
}

// RegisterDevice registers or refreshes a device by EID.
func (s *Store) RegisterDevice(ctx context.Context, tenantID storage.TenantID, device storage.Device) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, eid)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id, eid)
		DO UPDATE SET updated_at = now()
	`, tenantString(tenantID), device.EID)
	return err
}

// GetProfileState reads one device's profile state.
func (s *Store) GetProfileState(ctx context.Context, tenantID storage.TenantID, eid string) (storage.ProfileState, error) {
	var state storage.ProfileState
	err := s.pool.QueryRow(ctx, `
		SELECT eid, state_payload
		FROM profile_state
		WHERE tenant_id = $1 AND eid = $2
	`, tenantString(tenantID), eid).Scan(&state.EID, &state.Data)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.ProfileState{}, storage.ErrNotFound
	}
	return cloneProfileState(state), err
}

// SetProfileState stores one device's profile state.
func (s *Store) SetProfileState(ctx context.Context, tenantID storage.TenantID, state storage.ProfileState) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO profile_state (tenant_id, eid, state_payload)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, eid)
		DO UPDATE SET state_payload = EXCLUDED.state_payload, updated_at = now()
	`, tenantString(tenantID), state.EID, state.Data)
	if err != nil {
		if isForeignKeyViolation(err) {
			return storage.ErrNotFound
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// NextEUICCPackageCounter returns the next eUICC package counter and persists
// the increment atomically for this tenant and EID.
func (s *Store) NextEUICCPackageCounter(ctx context.Context, tenantID storage.TenantID, eid string) (int64, error) {
	var counter int64
	err := s.pool.QueryRow(ctx, `
		UPDATE devices
		SET next_euicc_package_counter = next_euicc_package_counter + 1, updated_at = now()
		WHERE tenant_id = $1 AND eid = $2
		RETURNING next_euicc_package_counter - 1
	`, tenantString(tenantID), eid).Scan(&counter)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, storage.ErrNotFound
	}
	return counter, err
}

// EnqueueOperation appends pending work for a device.
func (s *Store) EnqueueOperation(ctx context.Context, tenantID storage.TenantID, request storage.OperationRequest) (storage.Operation, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return storage.Operation{}, err
	}
	defer rollback(ctx, tx)

	tenant := tenantString(tenantID)
	var sequenceNumber int64
	err = tx.QueryRow(ctx, `
		UPDATE devices
		SET next_sequence_number = next_sequence_number + 1, updated_at = now()
		WHERE tenant_id = $1 AND eid = $2
		RETURNING next_sequence_number - 1
	`, tenant, request.EID).Scan(&sequenceNumber)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.Operation{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Operation{}, err
	}

	var operation storage.Operation
	err = tx.QueryRow(ctx, `
		INSERT INTO operations (tenant_id, eid, sequence_number, kind, payload, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, eid, sequence_number, kind, payload, status, created_at, updated_at
	`, tenant, request.EID, sequenceNumber, string(request.Kind), request.Payload, string(storage.OperationPending)).Scan(
		&operation.ID,
		&operation.EID,
		&operation.SequenceNumber,
		&operation.Kind,
		&operation.Payload,
		&operation.Status,
		&operation.CreatedAt,
		&operation.UpdatedAt,
	)
	if err != nil {
		return storage.Operation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return storage.Operation{}, err
	}
	return cloneOperation(operation), nil
}

// FetchPendingOperations returns pending operations in sequence order and marks
// them in-flight.
func (s *Store) FetchPendingOperations(ctx context.Context, tenantID storage.TenantID, eid string, limit int) ([]storage.Operation, error) {
	if limit <= 0 {
		return nil, nil
	}

	rows, err := s.pool.Query(ctx, `
		WITH selected AS (
			SELECT id
			FROM operations
			WHERE tenant_id = $1 AND eid = $2 AND status = $3
			ORDER BY sequence_number
			LIMIT $4
			FOR UPDATE SKIP LOCKED
		), updated AS (
			UPDATE operations AS operation
			SET status = $5, updated_at = now()
			FROM selected
			WHERE operation.id = selected.id
			RETURNING operation.id, operation.eid, operation.sequence_number, operation.kind,
				operation.payload, operation.status, operation.created_at, operation.updated_at
		)
		SELECT id, eid, sequence_number, kind, payload, status, created_at, updated_at
		FROM updated
		ORDER BY sequence_number
	`, tenantString(tenantID), eid, string(storage.OperationPending), limit, string(storage.OperationInFlight))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	operations := make([]storage.Operation, 0)
	for rows.Next() {
		var operation storage.Operation
		if err := rows.Scan(
			&operation.ID,
			&operation.EID,
			&operation.SequenceNumber,
			&operation.Kind,
			&operation.Payload,
			&operation.Status,
			&operation.CreatedAt,
			&operation.UpdatedAt,
		); err != nil {
			return nil, err
		}
		operations = append(operations, cloneOperation(operation))
	}
	return operations, rows.Err()
}

// RecordEUICCPackageResult stores a result and marks the matching operation done
// or failed.
func (s *Store) RecordEUICCPackageResult(ctx context.Context, tenantID storage.TenantID, result storage.EUICCPackageResult) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)

	tenant := tenantString(tenantID)
	status := normalizeResultStatus(result.Status)
	if result.OperationID != 0 {
		err = tx.QueryRow(ctx, `
			SELECT eid, sequence_number
			FROM operations
			WHERE tenant_id = $1 AND id = $2
		`, tenant, result.OperationID).Scan(&result.EID, &result.SequenceNumber)
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		if err != nil {
			return err
		}
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO operation_results (tenant_id, eid, operation_id, sequence_number, status, payload)
		VALUES ($1, $2, NULLIF($3, 0), $4, $5, $6)
		ON CONFLICT (tenant_id, eid, sequence_number)
		DO UPDATE SET operation_id = EXCLUDED.operation_id, status = EXCLUDED.status,
			payload = EXCLUDED.payload, created_at = now()
	`, tenant, result.EID, result.OperationID, result.SequenceNumber, string(status), result.Payload)
	if err != nil {
		if isForeignKeyViolation(err) {
			return storage.ErrNotFound
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}

	if result.OperationID != 0 {
		_, err = tx.Exec(ctx, `
			UPDATE operations
			SET status = $3, updated_at = now()
			WHERE tenant_id = $1 AND id = $2
		`, tenant, result.OperationID, string(status))
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE operations
			SET status = $4, updated_at = now()
			WHERE tenant_id = $1 AND eid = $2 AND sequence_number = $3
		`, tenant, result.EID, result.SequenceNumber, string(status))
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// StoreEIMConfig stores an encoded eIM configuration.
func (s *Store) StoreEIMConfig(ctx context.Context, tenantID storage.TenantID, config storage.EIMConfig) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO eim_config (tenant_id, eim_id, config_payload)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, eim_id)
		DO UPDATE SET config_payload = EXCLUDED.config_payload, updated_at = now()
	`, tenantString(tenantID), config.EIMID, config.Data)
	return err
}

// ReadEIMConfig reads an encoded eIM configuration.
func (s *Store) ReadEIMConfig(ctx context.Context, tenantID storage.TenantID, eimID string) (storage.EIMConfig, error) {
	var config storage.EIMConfig
	err := s.pool.QueryRow(ctx, `
		SELECT eim_id, config_payload
		FROM eim_config
		WHERE tenant_id = $1 AND eim_id = $2
	`, tenantString(tenantID), eimID).Scan(&config.EIMID, &config.Data)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.EIMConfig{}, storage.ErrNotFound
	}
	return cloneEIMConfig(config), err
}

// StoreNotification stores an encoded device notification.
func (s *Store) StoreNotification(ctx context.Context, tenantID storage.TenantID, notification storage.Notification) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO notifications (tenant_id, eid, kind, payload)
		VALUES ($1, $2, $3, $4)
	`, tenantString(tenantID), notification.EID, notification.Kind, notification.Payload)
	if isForeignKeyViolation(err) {
		return storage.ErrNotFound
	}
	return err
}

func rollback(ctx context.Context, tx pgx.Tx) {
	_ = tx.Rollback(ctx)
}

func tenantString(tenantID storage.TenantID) string {
	return string(storage.NormalizeTenantID(tenantID))
}

func normalizeResultStatus(status storage.OperationStatus) storage.OperationStatus {
	if status == storage.OperationFailed {
		return storage.OperationFailed
	}
	return storage.OperationDone
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.ForeignKeyViolation
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
