package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openiotrsp/openiotrsp/dataact"
	appruntime "github.com/openiotrsp/openiotrsp/internal/app/runtime"
	"github.com/openiotrsp/openiotrsp/storage"
	storepg "github.com/openiotrsp/openiotrsp/storage/postgres"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger, os.Args[1:]); err != nil {
		logger.Error("eim command failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: eim import-bundle --database-url URL --tenant-id ID --bundle PATH [--trust-cert PATH]")
	}
	switch args[0] {
	case "import-bundle":
		return runImportBundle(logger, args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runImportBundle(logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("import-bundle", flag.ContinueOnError)
	databaseURL := fs.String("database-url", appruntime.Env("OPENIOTRSP_DATABASE_URL", "postgres://admin:secretpassword@localhost:5432/openiotrsp?sslmode=disable"), "Postgres connection URL")
	tenantID := fs.String("tenant-id", string(storage.DefaultTenantID), "Destination tenant id")
	bundlePath := fs.String("bundle", "", "Path to signed export ZIP")
	trustCertPath := fs.String("trust-cert", "", "Optional PEM certificate that signed the bundle")
	migrationsDir := fs.String("migrations-dir", appruntime.Env("OPENIOTRSP_MIGRATIONS_DIR", "migrations"), "SQL migrations directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return errors.New("--bundle is required")
	}

	var trustCert *x509.Certificate
	if *trustCertPath != "" {
		cert, err := loadCertificate(*trustCertPath)
		if err != nil {
			return err
		}
		trustCert = cert
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := appruntime.RunMigrations(*databaseURL, *migrationsDir); err != nil {
		return err
	}
	store, err := appruntime.OpenPostgres(ctx, *databaseURL, 30, time.Second)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := dataact.ImportBundle(ctx, store, storage.TenantID(*tenantID), *bundlePath, dataact.ImportOptions{
		TrustCert: trustCert,
	}); err != nil {
		return err
	}
	logger.Info("bundle imported", "tenantId", *tenantID)
	return nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust certificate: %w", err)
	}
	block, _ := pem.Decode(payload)
	if block == nil {
		return nil, errors.New("trust certificate is not PEM encoded")
	}
	return x509.ParseCertificate(block.Bytes)
}

var _ dataact.BundleImporter = (*storepg.Store)(nil)
