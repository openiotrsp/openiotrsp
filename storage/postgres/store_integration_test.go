//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	storepg "github.com/openiotrsp/openiotrsp/storage/postgres"
	"github.com/openiotrsp/openiotrsp/storage/storetest"
)

const postgresTestDSNEnv = "OPENIOTRSP_POSTGRES_TEST_DSN"

func TestMigrationRoundTrip(t *testing.T) {
	dsn := postgresTestDSN(t)
	logPostgresTarget(t, dsn)
	cleanDatabase(t, dsn)

	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Down()
	})
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})
}

func TestStoreConformance(t *testing.T) {
	dsn := postgresTestDSN(t)
	logPostgresTarget(t, dsn)
	cleanDatabase(t, dsn)
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})

	storetest.Run(t, func(t testing.TB) storage.Store {
		t.Helper()
		store, err := storepg.Open(context.Background(), dsn)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		t.Cleanup(store.Close)
		return store
	})
}

func TestDefaultTenantInserted(t *testing.T) {
	dsn := postgresTestDSN(t)
	logPostgresTarget(t, dsn)
	cleanDatabase(t, dsn)
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})

	ctx := context.Background()
	store, err := storepg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)

	eid := "eid-default-tenant"
	if err := store.RegisterDevice(ctx, "", storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)

	var tenantID string
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM devices WHERE eid = $1`, eid).Scan(&tenantID); err != nil {
		t.Fatalf("query tenant_id error = %v", err)
	}
	if tenantID != string(storage.DefaultTenantID) {
		t.Fatalf("tenant_id = %q, want %q", tenantID, storage.DefaultTenantID)
	}
}

func TestEUICCPackageCounterConcurrentSameEID(t *testing.T) {
	dsn := postgresTestDSN(t)
	logPostgresTarget(t, dsn)
	cleanDatabase(t, dsn)
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})

	ctx := context.Background()
	store, err := storepg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)

	const requestCount = 100
	eid := "eid-postgres-counter-stress"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, requestCount)
	counters := make(chan int64, requestCount)
	var wg sync.WaitGroup
	wg.Add(requestCount)
	for range requestCount {
		go func() {
			defer wg.Done()
			<-start
			counter, err := store.NextEUICCPackageCounter(ctx, storage.DefaultTenantID, eid)
			if err != nil {
				errs <- err
				return
			}
			counters <- counter
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(counters)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[int64]bool, requestCount)
	for counter := range counters {
		if counter < 1 || counter > requestCount {
			t.Fatalf("counter %d outside 1..%d", counter, requestCount)
		}
		if seen[counter] {
			t.Fatalf("duplicate counterValue %d for EID %s", counter, eid)
		}
		seen[counter] = true
	}
	if len(seen) != requestCount {
		t.Fatalf("saw %d unique counters, want %d", len(seen), requestCount)
	}
}

func TestOperationRedeliversUntilResultRecorded(t *testing.T) {
	dsn := postgresTestDSN(t)
	logPostgresTarget(t, dsn)
	cleanDatabase(t, dsn)
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})

	ctx := context.Background()
	store, err := storepg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)

	eidBytes := postgresTestEID(0x81)
	eid := hex.EncodeToString(eidBytes)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	payload := postgresEncode(t, postgresSampleEuiccPackageRequest(eidBytes, 42))
	queued, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationEuiccPackage,
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	first := fetchOnePendingOperation(t, store, ctx, eid)
	if first.ID != queued.ID || first.SequenceNumber != queued.SequenceNumber {
		t.Fatalf("first fetch = id %d seq %d, want id %d seq %d", first.ID, first.SequenceNumber, queued.ID, queued.SequenceNumber)
	}
	if first.Status != storage.OperationPending {
		t.Fatalf("first fetch status = %s, want pending", first.Status)
	}
	if !bytes.Equal(first.Payload, payload) {
		t.Fatalf("first fetch payload changed")
	}
	if got := postgresDecodeEuiccPackage(t, first.Payload).EuiccPackageSigned.CounterValue; got != 42 {
		t.Fatalf("first fetch counterValue = %d, want 42", got)
	}

	second := fetchOnePendingOperation(t, store, ctx, eid)
	if second.ID != first.ID || second.SequenceNumber != first.SequenceNumber {
		t.Fatalf("redelivery = id %d seq %d, want id %d seq %d", second.ID, second.SequenceNumber, first.ID, first.SequenceNumber)
	}
	if !bytes.Equal(second.Payload, first.Payload) {
		t.Fatalf("redelivered payload changed")
	}
	if got := postgresDecodeEuiccPackage(t, second.Payload).EuiccPackageSigned.CounterValue; got != 42 {
		t.Fatalf("redelivered counterValue = %d, want 42", got)
	}

	if err := store.RecordEUICCPackageResult(ctx, storage.DefaultTenantID, storage.EUICCPackageResult{
		EID:            eid,
		OperationID:    second.ID,
		SequenceNumber: second.SequenceNumber,
		Status:         storage.OperationDone,
		Payload:        []byte{0x30, 0x03, 0x02, 0x01, 0x00},
	}); err != nil {
		t.Fatalf("RecordEUICCPackageResult() error = %v", err)
	}
	afterResult, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eid, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations(after result) error = %v", err)
	}
	if len(afterResult) != 0 {
		t.Fatalf("FetchPendingOperations(after result) returned %d operations, want 0", len(afterResult))
	}
}

func TestConcurrentOperationPollsDoNotCorruptRedeliveryState(t *testing.T) {
	dsn := postgresTestDSN(t)
	logPostgresTarget(t, dsn)
	cleanDatabase(t, dsn)
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})

	ctx := context.Background()
	store, err := storepg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)

	eidBytes := postgresTestEID(0x82)
	eid := hex.EncodeToString(eidBytes)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	payload := postgresEncode(t, postgresSampleEuiccPackageRequest(eidBytes, 77))
	queued, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationEuiccPackage,
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	results := make(chan storage.Operation, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			<-start
			operations, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eid, 1)
			if err != nil {
				errs <- err
				return
			}
			if len(operations) != 1 {
				errs <- fmt.Errorf("FetchPendingOperations() returned %d operations, want 1", len(operations))
				return
			}
			results <- operations[0]
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(results)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	polls := make([]storage.Operation, 0, 2)
	for operation := range results {
		polls = append(polls, operation)
	}
	if len(polls) != 2 {
		t.Fatalf("collected %d poll results, want 2", len(polls))
	}
	for _, poll := range polls {
		if poll.ID != queued.ID || poll.SequenceNumber != queued.SequenceNumber {
			t.Fatalf("concurrent poll = id %d seq %d, want id %d seq %d", poll.ID, poll.SequenceNumber, queued.ID, queued.SequenceNumber)
		}
		if poll.Status != storage.OperationPending {
			t.Fatalf("concurrent poll status = %s, want pending", poll.Status)
		}
		if !bytes.Equal(poll.Payload, payload) {
			t.Fatalf("concurrent poll payload changed")
		}
		if got := postgresDecodeEuiccPackage(t, poll.Payload).EuiccPackageSigned.CounterValue; got != 77 {
			t.Fatalf("concurrent poll counterValue = %d, want 77", got)
		}
	}

	if err := store.RecordEUICCPackageResult(ctx, storage.DefaultTenantID, storage.EUICCPackageResult{
		EID:            eid,
		OperationID:    queued.ID,
		SequenceNumber: queued.SequenceNumber,
		Status:         storage.OperationDone,
		Payload:        []byte{0x30, 0x03, 0x02, 0x01, 0x00},
	}); err != nil {
		t.Fatalf("RecordEUICCPackageResult() error = %v", err)
	}
	afterResult, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eid, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations(after result) error = %v", err)
	}
	if len(afterResult) != 0 {
		t.Fatalf("FetchPendingOperations(after result) returned %d operations, want 0", len(afterResult))
	}
}

func postgresTestDSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv(postgresTestDSNEnv)
	if dsn == "" {
		t.Fatalf("%s is required for Postgres integration tests; start Postgres explicitly and set the DSN", postgresTestDSNEnv)
	}
	return dsn
}

func logPostgresTarget(t testing.TB, dsn string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	defer pool.Close()

	var database string
	var serverAddress *string
	var serverPort *int
	var serverVersion string
	err = pool.QueryRow(ctx, `
		SELECT current_database(), inet_server_addr()::text, inet_server_port(), current_setting('server_version')
	`).Scan(&database, &serverAddress, &serverPort, &serverVersion)
	if err != nil {
		t.Fatalf("query Postgres target error = %v", err)
	}
	t.Logf("Postgres integration target: dsn=%s database=%s server=%s:%s version=%s",
		redactDSN(dsn),
		database,
		stringValue(serverAddress),
		intValue(serverPort),
		serverVersion,
	)
}

func redactDSN(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.User == nil {
		return dsn
	}
	if username := parsed.User.Username(); username != "" {
		parsed.User = url.UserPassword(username, "xxxxx")
	}
	return parsed.String()
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func intValue(value *int) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(*value)
}

func cleanDatabase(t testing.TB, dsn string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	defer pool.Close()

	_, err = pool.Exec(ctx, `
		DROP TABLE IF EXISTS notifications;
		DROP TABLE IF EXISTS eim_config;
		DROP TABLE IF EXISTS operation_results;
		DROP TABLE IF EXISTS operations;
		DROP INDEX IF EXISTS profile_state_device_idx;
		DROP TABLE IF EXISTS profile_state;
		DROP TABLE IF EXISTS devices;
		DROP TABLE IF EXISTS schema_migrations;
	`)
	if err != nil {
		t.Fatalf("clean database error = %v", err)
	}
}

func runMigration(t testing.TB, dsn string, run func(*migrate.Migrate) error) {
	t.Helper()
	migration, err := migrate.New(migrationSourceURL(t), migrationDatabaseURL(t, dsn))
	if err != nil {
		t.Fatalf("migrate.New() error = %v", err)
	}
	defer func() {
		sourceErr, databaseErr := migration.Close()
		if sourceErr != nil || databaseErr != nil {
			t.Fatalf("migration close errors: source=%v database=%v", sourceErr, databaseErr)
		}
	}()

	if err := run(migration); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migration error = %v", err)
	}
}

func migrationSourceURL(t testing.TB) string {
	t.Helper()
	path, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("migration path error = %v", err)
	}
	return fmt.Sprintf("file://%s", filepath.ToSlash(path))
}

func migrationDatabaseURL(t testing.TB, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse database URL error = %v", err)
	}
	parsed.Scheme = "pgx5"
	return parsed.String()
}

func fetchOnePendingOperation(t testing.TB, store storage.Store, ctx context.Context, eid string) storage.Operation {
	t.Helper()
	operations, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eid, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(operations) != 1 {
		t.Fatalf("FetchPendingOperations() returned %d operations, want 1", len(operations))
	}
	return operations[0]
}

func postgresEncode(t testing.TB, value protocolasn1.Marshaler) []byte {
	t.Helper()
	payload, err := protocolasn1.Encode(value)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	return payload
}

func postgresDecodeEuiccPackage(t testing.TB, payload []byte) protocolasn1.EuiccPackageRequest {
	t.Helper()
	var request protocolasn1.EuiccPackageRequest
	if err := protocolasn1.Decode(payload, &request); err != nil {
		t.Fatalf("Decode(EuiccPackageRequest) error = %v", err)
	}
	return request
}

func postgresSampleEuiccPackageRequest(eid []byte, counterValue int64) *protocolasn1.EuiccPackageRequest {
	return &protocolasn1.EuiccPackageRequest{
		EuiccPackageSigned: protocolasn1.EuiccPackageSigned{
			EimID:        "testeim1",
			EID:          append([]byte(nil), eid...),
			CounterValue: counterValue,
			EuiccPackage: protocolasn1.EuiccPackage{
				Kind: protocolasn1.EuiccPackagePSMO,
				PSMOs: []protocolasn1.Psmo{{
					Operation: protocolasn1.PsmoEnable,
					ICCID:     []byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1},
				}},
			},
		},
		EimSignature: []byte{0xa5, 0xa5, 0xa5},
	}
}

func postgresTestEID(last byte) []byte {
	eid := make([]byte, 16)
	eid[15] = last
	return eid
}
