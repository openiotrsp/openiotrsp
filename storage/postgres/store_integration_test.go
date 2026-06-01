//go:build integration

package postgres_test

import (
	"context"
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
