//go:build load

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	appruntime "github.com/openiotrsp/openiotrsp/internal/app/runtime"
	"github.com/openiotrsp/openiotrsp/storage"
	storepg "github.com/openiotrsp/openiotrsp/storage/postgres"
)

const loadPostgresDSNEnv = "OPENIOTRSP_POSTGRES_TEST_DSN"

func TestLoadQueues10000OperationsInPostgres(t *testing.T) {
	dsn := os.Getenv(loadPostgresDSNEnv)
	if dsn == "" {
		if os.Getenv("CI") != "" || os.Getenv("OPENIOTRSP_REQUIRE_POSTGRES_TEST_DSN") == "1" {
			t.Fatalf("%s is required for load tests", loadPostgresDSNEnv)
		}
		t.Skipf("%s is not set; skipping Postgres load test", loadPostgresDSNEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cleanLoadDatabase(t, ctx, dsn)
	if err := appruntime.RunMigrations(dsn, filepath.Join("..", "migrations")); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	store, err := storepg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)

	server := newTestServer(t, store, DefaultTenantResolver{})
	const operationCount = 10000
	const workerCount = 100
	start := make(chan struct{})
	errs := make(chan error, operationCount)
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for worker := range workerCount {
		worker := worker
		go func() {
			defer wg.Done()
			<-start
			for index := worker; index < operationCount; index += workerCount {
				response := doRequest(t, server, http.MethodPost, "/v1/profile-downloads", jsonBody(t, map[string]any{
					"eid":            testEID,
					"activationCode": fmt.Sprintf("1$smdpp.example$load-%05d", index),
				}))
				if response.Code != http.StatusAccepted {
					errs <- fmt.Errorf("request %d status = %d body = %s", index, response.Code, response.Body.String())
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, testEID, operationCount+1)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != operationCount {
		t.Fatalf("persisted operations = %d, want %d", len(pending), operationCount)
	}
	seenSequences := make(map[int64]bool, operationCount)
	seenIDs := make(map[int64]bool, operationCount)
	for _, operation := range pending {
		if seenIDs[operation.ID] {
			t.Fatalf("duplicate operation id %d", operation.ID)
		}
		seenIDs[operation.ID] = true
		if operation.SequenceNumber < 1 || operation.SequenceNumber > operationCount {
			t.Fatalf("sequence number %d outside 1..%d", operation.SequenceNumber, operationCount)
		}
		if seenSequences[operation.SequenceNumber] {
			t.Fatalf("duplicate sequence number %d", operation.SequenceNumber)
		}
		seenSequences[operation.SequenceNumber] = true
	}
}

func cleanLoadDatabase(t testing.TB, ctx context.Context, dsn string) {
	t.Helper()
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
		t.Fatalf("clean load database error = %v", err)
	}
}

func jsonBody(t *testing.T, body any) *bytes.Reader {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return bytes.NewReader(payload)
}
