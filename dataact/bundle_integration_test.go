//go:build integration

package dataact_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/openiotrsp/openiotrsp/dataact"
	"github.com/openiotrsp/openiotrsp/storage"
	storepg "github.com/openiotrsp/openiotrsp/storage/postgres"
)

const postgresTestDSNEnv = "OPENIOTRSP_POSTGRES_TEST_DSN"

func TestBundleValidateAndImportRoundTrip(t *testing.T) {
	dsn := postgresTestDSN(t)
	bundlePath := filepath.Join("testdata", "minimal-bundle.zip")
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("missing committed fixture %s: %v", bundlePath, err)
	}

	manifest, err := dataact.ValidateBundle(bundlePath, nil)
	if err != nil {
		t.Fatalf("ValidateBundle() error = %v", err)
	}
	if manifest.SchemaVersion != dataact.SchemaVersion {
		t.Fatalf("schema version = %q, want %q", manifest.SchemaVersion, dataact.SchemaVersion)
	}

	journal, err := dataact.ReadJournalRecords(bundlePath)
	if err != nil {
		t.Fatalf("ReadJournalRecords() error = %v", err)
	}
	if err := dataact.VerifyJournalSlice(manifest.TenantID, journal, manifest.JournalChain); err != nil {
		t.Fatalf("VerifyJournalSlice() error = %v", err)
	}

	ctx := context.Background()
	cleanDatabase(t, dsn)
	runMigrationsUp(t, dsn)

	store, err := storepg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	tenantID := storage.TenantID("import-roundtrip")
	eid := "89049032000000000000000000000001"
	if err := dataact.ImportBundle(ctx, store, tenantID, bundlePath, dataact.ImportOptions{}); err != nil {
		t.Fatalf("ImportBundle() error = %v", err)
	}

	states, err := store.ListProfileStates(ctx, tenantID, eid)
	if err != nil {
		t.Fatalf("ListProfileStates() error = %v", err)
	}
	if len(states) != 1 || !states[0].IsEnabled {
		t.Fatalf("profile state = %#v, want one enabled profile", states)
	}

	// Fixture devices.ndjson has nextSequenceNumber=2 and nextEuiccPackageCounter=2.
	counter, err := store.NextEUICCPackageCounter(ctx, tenantID, eid)
	if err != nil {
		t.Fatalf("NextEUICCPackageCounter() error = %v", err)
	}
	if counter != 2 {
		t.Fatalf("next euicc package counter = %d, want 2", counter)
	}
	operation, err := store.EnqueueOperation(ctx, tenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationIpaEuiccData,
		Payload: []byte{0x01},
	})
	if err != nil {
		t.Fatalf("EnqueueOperation() error = %v", err)
	}
	if operation.SequenceNumber != 2 {
		t.Fatalf("next sequence number = %d, want 2", operation.SequenceNumber)
	}
}


func postgresTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(postgresTestDSNEnv)
	if dsn == "" {
		t.Skip(postgresTestDSNEnv + " not set")
	}
	return dsn
}

func cleanDatabase(t *testing.T, dsn string) {
	t.Helper()
	runMigrations(t, dsn, func(m *migrate.Migrate) error {
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			return err
		}
		return m.Up()
	})
}

func runMigrationsUp(t *testing.T, dsn string) {
	t.Helper()
	runMigrations(t, dsn, func(m *migrate.Migrate) error {
		return m.Up()
	})
}

func runMigrations(t *testing.T, dsn string, fn func(*migrate.Migrate) error) {
	t.Helper()
	migrationsDir, err := filepath.Abs(filepath.Join("..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations dir: %v", err)
	}
	m, err := migrate.New("file://"+filepath.ToSlash(migrationsDir), dsn)
	if err != nil {
		t.Fatalf("migrate.New() error = %v", err)
	}
	defer m.Close()
	if err := fn(m); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migration error = %v", err)
	}
}
