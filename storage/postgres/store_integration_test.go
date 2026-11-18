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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
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
	assertMigrationVersion(t, dsn, 6, false)
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Down()
	})
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})
	assertMigrationVersion(t, dsn, 6, false)
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
		if requirePostgresTestDSN() {
			t.Fatalf("%s is required for Postgres integration tests in CI; start Postgres explicitly and set the DSN", postgresTestDSNEnv)
		}
		t.Skipf("%s is not set; skipping Postgres integration tests", postgresTestDSNEnv)
	}
	return dsn
}

func requirePostgresTestDSN() bool {
	return os.Getenv("CI") != "" || os.Getenv("OPENIOTRSP_REQUIRE_POSTGRES_TEST_DSN") == "1"
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
		DROP INDEX IF EXISTS notifications_sequence_idx;
		DROP INDEX IF EXISTS notifications_device_idx;
		DROP TABLE IF EXISTS notifications;
		DROP TABLE IF EXISTS euicc_state;
		DROP TABLE IF EXISTS associated_eim;
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

func assertMigrationVersion(t testing.TB, dsn string, wantVersion int, wantDirty bool) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	defer pool.Close()

	var version int
	var dirty bool
	if err := pool.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("query schema_migrations error = %v", err)
	}
	if version != wantVersion || dirty != wantDirty {
		t.Fatalf("schema_migrations = version %d dirty %v, want version %d dirty %v", version, dirty, wantVersion, wantDirty)
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

// TestRecordEUICCPackageResultFailureDoesNotOverwriteConcurrentDone forces the
// interleaving where a failed result reads the operation as pending, a done
// result for the same operation then commits, and only afterwards does the
// failed result reach its first write. Without a row lock on the status SELECT
// (SELECT ... FOR UPDATE) the failure overwrites the committed success, so this
// test fails. With the row lock, the failed call holds the row, the done call
// waits on it, and done is written last, so this test passes.
//
// Ordering uses Postgres locks, not sleeps: a test-only BEFORE INSERT trigger on
// operation_results makes non-done inserts for this EID take
// pg_advisory_xact_lock(K), while the test holds K on its own connection.
func TestRecordEUICCPackageResultFailureDoesNotOverwriteConcurrentDone(t *testing.T) {
	dsn := postgresTestDSN(t)
	logPostgresTarget(t, dsn)
	cleanDatabase(t, dsn)
	runMigration(t, dsn, func(migration *migrate.Migrate) error {
		return migration.Up()
	})

	store, err := storepg.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)

	cases := []struct {
		name          string
		eidLast       byte
		lockKey       int32
		byOperationID bool
	}{
		{name: "ByOperationID", eidLast: 0x91, lockKey: 1, byOperationID: true},
		{name: "ByEIDAndSequenceNumber", eidLast: 0x92, lockKey: 2, byOperationID: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runResultRaceCase(t, dsn, store, tc.eidLast, tc.lockKey, tc.byOperationID)
		})
	}
}

// resultRaceLockClass is the first key of the two-int advisory lock used by
// TestRecordEUICCPackageResultFailureDoesNotOverwriteConcurrentDone.
const resultRaceLockClass int32 = 0x50475243 // "PGRC"

func runResultRaceCase(t *testing.T, dsn string, store *storepg.Store, eidLast byte, lockKey int32, byOperationID bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eidBytes := postgresTestEID(eidLast)
	eid := hex.EncodeToString(eidBytes)
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	queued, err := store.EnqueueOperation(ctx, storage.DefaultTenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationEuiccPackage,
		Payload: postgresEncode(t, postgresSampleEuiccPackageRequest(eidBytes, 7)),
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}
	pending, err := store.GetOperation(ctx, storage.DefaultTenantID, queued.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if pending.Status != storage.OperationPending {
		t.Fatalf("initial status = %s, want pending", pending.Status)
	}

	// Test-only trigger: a non-done result insert for this EID blocks on K.
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect(admin) error = %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	suffix := fmt.Sprintf("%d_%d", os.Getpid(), lockKey)
	function := "test_result_race_gate_" + suffix
	trigger := "test_result_race_gate_trg_" + suffix
	_, err = admin.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $fn$
		BEGIN
			IF NEW.eid = %[2]s AND NEW.status <> 'done' THEN
				PERFORM pg_advisory_xact_lock(%[3]d, %[4]d);
			END IF;
			RETURN NEW;
		END
		$fn$;
		CREATE TRIGGER %[5]s BEFORE INSERT ON operation_results
			FOR EACH ROW EXECUTE FUNCTION %[1]s();
	`, function, quoteLiteral(eid), resultRaceLockClass, lockKey, trigger))
	if err != nil {
		t.Fatalf("create gate trigger error = %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, err := admin.Exec(cleanupCtx, fmt.Sprintf(
			`DROP TRIGGER IF EXISTS %s ON operation_results; DROP FUNCTION IF EXISTS %s();`, trigger, function))
		if err != nil {
			t.Errorf("drop gate trigger error = %v", err)
		}
	})

	// Hold K on a dedicated session connection.
	holder, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect(holder) error = %v", err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock($1, $2)`, resultRaceLockClass, lockKey); err != nil {
		_ = holder.Close(context.Background())
		t.Fatalf("pg_advisory_lock error = %v", err)
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		released = true
		var ok bool
		err := holder.QueryRow(ctx, `SELECT pg_advisory_unlock($1, $2)`, resultRaceLockClass, lockKey).Scan(&ok)
		if err == nil && !ok {
			err = errors.New("pg_advisory_unlock returned false")
		}
		return err
	}

	successPayload := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	failedPayload := []byte{0x30, 0x03, 0x02, 0x01, 0x7f}
	newResult := func(status storage.OperationStatus, payload []byte) storage.EUICCPackageResult {
		result := storage.EUICCPackageResult{
			EID:            eid,
			SequenceNumber: queued.SequenceNumber,
			Status:         status,
			Payload:        payload,
		}
		if byOperationID {
			result.OperationID = queued.ID
		}
		return result
	}

	failedDone := make(chan error, 1)
	successDone := make(chan error, 1)
	var wg sync.WaitGroup
	// On any exit: free K (closing the session also frees it), cancel the
	// calls' context, then wait so no goroutine outlives the subtest.
	defer func() {
		_ = release()
		_ = holder.Close(context.Background())
		cancel()
		wg.Wait()
	}()

	// 1. failed: reads pending, then blocks in the trigger on K.
	wg.Add(1)
	go func() {
		defer wg.Done()
		failedDone <- store.RecordEUICCPackageResult(ctx, storage.DefaultTenantID, newResult(storage.OperationFailed, failedPayload))
	}()
	failedPID, err := waitForAdvisoryWaiter(ctx, admin, lockKey, failedDone)
	if err != nil {
		t.Fatalf("waiting for failed call to block on gate: %v", err)
	}

	// 2. done: either commits (no row lock) or waits on the row lock held by
	// the failed call (row lock present).
	wg.Add(1)
	go func() {
		defer wg.Done()
		successDone <- store.RecordEUICCPackageResult(ctx, storage.DefaultTenantID, newResult(storage.OperationDone, successPayload))
	}()
	var successErr error
	successReturned, err := waitForReturnOrBlockedBy(ctx, admin, failedPID, successDone, &successErr)
	if err != nil {
		t.Fatalf("waiting for done call to commit or lock-wait: %v", err)
	}
	if successReturned {
		t.Logf("done call committed while failed call was gated (status SELECT took no row lock)")
	} else {
		t.Logf("done call is waiting on a lock held by the failed call (pid %d)", failedPID)
	}

	// 3. Let the failed call continue to its write.
	if err := release(); err != nil {
		t.Fatalf("release gate error = %v", err)
	}
	var failedErr error
	select {
	case failedErr = <-failedDone:
	case <-ctx.Done():
		t.Fatalf("failed call did not return: %v", ctx.Err())
	}
	if !successReturned {
		select {
		case successErr = <-successDone:
		case <-ctx.Done():
			t.Fatalf("done call did not return: %v", ctx.Err())
		}
	}
	if failedErr != nil {
		t.Fatalf("RecordEUICCPackageResult(failed) error = %v", failedErr)
	}
	if successErr != nil {
		t.Fatalf("RecordEUICCPackageResult(done) error = %v", successErr)
	}

	// 4. A saved success must survive.
	operation, err := store.GetOperation(ctx, storage.DefaultTenantID, queued.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if operation.Status != storage.OperationDone {
		t.Errorf("operations.status = %s, want done (failure overwrote a saved success)", operation.Status)
	}
	stored, err := store.GetOperationResult(ctx, storage.DefaultTenantID, queued.ID)
	if err != nil {
		t.Fatalf("GetOperationResult() error = %v", err)
	}
	if stored.Status != storage.OperationDone {
		t.Errorf("operation_results.status = %s, want done", stored.Status)
	}
	if !bytes.Equal(stored.Payload, successPayload) {
		t.Errorf("operation_results.payload = %x, want success payload %x", stored.Payload, successPayload)
	}
}

// waitForAdvisoryWaiter polls pg_locks until a backend waits (granted = false)
// on the gate advisory lock and returns its pid. It fails if the gated call
// returns first, because then the trigger never blocked it.
func waitForAdvisoryWaiter(ctx context.Context, conn *pgx.Conn, lockKey int32, done <-chan error) (int32, error) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var pid int32
		err := conn.QueryRow(ctx, `
			SELECT l.pid
			FROM pg_locks l
			JOIN pg_database d ON d.oid = l.database
			WHERE l.locktype = 'advisory'
				AND d.datname = current_database()
				AND l.classid::bigint = $1
				AND l.objid::bigint = $2
				AND l.objsubid = 2
				AND NOT l.granted
			LIMIT 1
		`, int64(resultRaceLockClass), int64(lockKey)).Scan(&pid)
		if err == nil {
			return pid, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		select {
		case callErr := <-done:
			return 0, fmt.Errorf("call returned before blocking on the gate (err = %v)", callErr)
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

// waitForReturnOrBlockedBy waits until the call reports on done (returned =
// true, its error stored in *callErr) or until some backend in this database
// is in a Lock wait that blockerPID causes (returned = false). The advisory
// waiter itself is blocked by the test's holder, not by blockerPID, so it never
// matches.
func waitForReturnOrBlockedBy(ctx context.Context, conn *pgx.Conn, blockerPID int32, done <-chan error, callErr *error) (bool, error) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			*callErr = err
			return true, nil
		default:
		}
		var blocked bool
		err := conn.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_stat_activity a
				WHERE a.datname = current_database()
					AND a.pid <> pg_backend_pid()
					AND a.pid <> $1
					AND a.wait_event_type = 'Lock'
					AND $1 = ANY (pg_blocking_pids(a.pid))
			)
		`, blockerPID).Scan(&blocked)
		if err != nil {
			return false, err
		}
		if blocked {
			return false, nil
		}
		select {
		case err := <-done:
			*callErr = err
			return true, nil
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
		}
	}
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
