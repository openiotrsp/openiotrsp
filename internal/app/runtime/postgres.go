package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/openiotrsp/openiotrsp/storage/postgres"
)

// OpenPostgres opens Postgres with retry so compose startup is deterministic.
func OpenPostgres(ctx context.Context, databaseURL string, attempts int, delay time.Duration) (*postgres.Store, error) {
	if attempts <= 0 {
		attempts = 1
	}
	if delay <= 0 {
		delay = time.Second
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		store, err := postgres.Open(ctx, databaseURL)
		if err == nil {
			return store, nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, fmt.Errorf("open postgres after %d attempts: %w", attempts, lastErr)
}

// RunMigrations applies database migrations from migrationsDir.
func RunMigrations(databaseURL, migrationsDir string) error {
	if databaseURL == "" {
		return errors.New("runtime: missing database URL")
	}
	if migrationsDir == "" {
		return errors.New("runtime: missing migrations directory")
	}
	abs, err := filepath.Abs(migrationsDir)
	if err != nil {
		return fmt.Errorf("resolve migrations directory: %w", err)
	}
	migration, err := migrate.New("file://"+filepath.ToSlash(abs), migrationDatabaseURL(databaseURL))
	if err != nil {
		return fmt.Errorf("create migration runner: %w", err)
	}
	defer func() {
		_, _ = migration.Close()
	}()
	if err := migration.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}

func migrationDatabaseURL(databaseURL string) string {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return databaseURL
	}
	parsed.Scheme = "pgx5"
	return parsed.String()
}
