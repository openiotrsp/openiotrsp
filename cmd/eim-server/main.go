package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openiotrsp/openiotrsp/api"
	"github.com/openiotrsp/openiotrsp/esipa"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	appruntime "github.com/openiotrsp/openiotrsp/internal/app/runtime"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	relaypkg "github.com/openiotrsp/openiotrsp/relay"
	filesigner "github.com/openiotrsp/openiotrsp/signing/file"
	"github.com/openiotrsp/openiotrsp/storage"
)

const (
	defaultDatabaseURL = "postgres://admin:secretpassword@postgres:5432/openiotrsp?sslmode=disable"
	defaultEID         = "89049032000000000000000000000001"
)

type config struct {
	databaseURL                 string
	migrationsDir               string
	listenAddr                  string
	eid                         string
	eimID                       string
	eimKeyPath                  string
	eimCertPath                 string
	euiccCertPath               string
	eumCertPath                 string
	ciCertPath                  string
	activationCode              string
	enqueueOnStart              bool
	allowUnverifiedEUICCResults bool
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("eIM server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := appruntime.RunMigrations(cfg.databaseURL, cfg.migrationsDir); err != nil {
		return err
	}
	store, err := appruntime.OpenPostgres(ctx, cfg.databaseURL, 30, time.Second)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := seedDemo(ctx, store, cfg, logger); err != nil {
		return err
	}
	packageService, err := loadPackageService(cfg)
	if err != nil {
		return err
	}
	euiccPublicKey, err := loadEUICCPublicKeyResolver(cfg)
	if err != nil {
		return err
	}

	started := time.Now()
	mux := http.NewServeMux()
	handler := esipa.NewHandler(store, storage.DefaultTenantID)
	handler.EUICCPublicKey = euiccPublicKey
	handler.AllowUnverifiedEUICCPackageResults = cfg.allowUnverifiedEUICCResults
	handler.Relay = relaypkg.New(relaypkg.HTTPTransport{})
	mux.HandleFunc(esipa.DefaultPath, handler.ServeHTTP)
	mux.Handle("/v1/", api.NewHTTPHandler(store, api.DefaultTenantResolver{}, packageService))
	mux.Handle("/healthz", appruntime.HealthHandler("eim-server", started))
	mux.HandleFunc("/status", statusHandler(ctx, store, cfg.eid))

	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("eIM server listening", "addr", cfg.listenAddr, "eid", cfg.eid)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func loadConfig() config {
	activationCode := appruntime.Env("OPENIOTRSP_DEMO_ACTIVATION_CODE", "")
	if activationCode == "" {
		smdpAddress := appruntime.Env("OPENIOTRSP_DEMO_SMDP_ADDRESS", "smdpp.test.rsp.sysmocom.de")
		matchingID := appruntime.Env("OPENIOTRSP_DEMO_MATCHING_ID", "TS48V1-B-UNIQUE")
		activationCode = "1$" + smdpAddress + "$" + matchingID
	}
	return config{
		databaseURL:                 appruntime.Env("OPENIOTRSP_DATABASE_URL", defaultDatabaseURL),
		migrationsDir:               appruntime.Env("OPENIOTRSP_MIGRATIONS_DIR", "migrations"),
		listenAddr:                  appruntime.Env("OPENIOTRSP_EIM_LISTEN_ADDR", ":8080"),
		eid:                         appruntime.Env("OPENIOTRSP_DEMO_EID", defaultEID),
		eimID:                       appruntime.Env("OPENIOTRSP_EIM_ID", "openiotrsp.eim"),
		eimKeyPath:                  appruntime.Env("OPENIOTRSP_EIM_KEY_PATH", ""),
		eimCertPath:                 appruntime.Env("OPENIOTRSP_EIM_CERT_PATH", ""),
		euiccCertPath:               appruntime.Env("OPENIOTRSP_EUICC_CERT_PATH", ""),
		eumCertPath:                 appruntime.Env("OPENIOTRSP_EUM_CERT_PATH", ""),
		ciCertPath:                  appruntime.Env("OPENIOTRSP_CI_CERT_PATH", ""),
		activationCode:              activationCode,
		enqueueOnStart:              appruntime.EnvBool("OPENIOTRSP_DEMO_ENQUEUE_ON_START", true),
		allowUnverifiedEUICCResults: appruntime.EnvBool("OPENIOTRSP_ALLOW_UNVERIFIED_EUICC_RESULTS", false),
	}
}

func loadPackageService(cfg config) (*euiccpkg.Service, error) {
	if cfg.eimKeyPath == "" && cfg.eimCertPath == "" {
		return nil, nil
	}
	if cfg.eimKeyPath == "" || cfg.eimCertPath == "" {
		return nil, errors.New("both OPENIOTRSP_EIM_KEY_PATH and OPENIOTRSP_EIM_CERT_PATH are required for signed eUICC package API endpoints")
	}
	signer, err := filesigner.Load(cfg.eimKeyPath, cfg.eimCertPath)
	if err != nil {
		return nil, err
	}
	return &euiccpkg.Service{
		Signer: signer,
		EimID:  cfg.eimID,
	}, nil
}

func loadEUICCPublicKeyResolver(cfg config) (esipa.EUICCPublicKeyResolver, error) {
	if cfg.euiccCertPath == "" && cfg.eumCertPath == "" && cfg.ciCertPath == "" {
		return nil, nil
	}
	if cfg.euiccCertPath == "" || cfg.eumCertPath == "" || cfg.ciCertPath == "" {
		return nil, errors.New("OPENIOTRSP_EUICC_CERT_PATH, OPENIOTRSP_EUM_CERT_PATH, and OPENIOTRSP_CI_CERT_PATH are required together for ESipa eUICC result verification")
	}
	euiccDER, err := os.ReadFile(cfg.euiccCertPath)
	if err != nil {
		return nil, err
	}
	eumDER, err := os.ReadFile(cfg.eumCertPath)
	if err != nil {
		return nil, err
	}
	ciDER, err := os.ReadFile(cfg.ciCertPath)
	if err != nil {
		return nil, err
	}
	return esipa.NewStaticEUICCCertificateResolver(ciDER, eumDER, euiccDER)
}

func seedDemo(ctx context.Context, store storage.Store, cfg config, logger *slog.Logger) error {
	if _, err := hex.DecodeString(cfg.eid); err != nil {
		return err
	}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: cfg.eid}); err != nil {
		return err
	}
	if !cfg.enqueueOnStart {
		return nil
	}
	states, err := store.ListProfileStates(ctx, storage.DefaultTenantID, cfg.eid)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	for _, state := range states {
		if state.IsEnabled {
			logger.Info("demo profile already enabled; not enqueueing another trigger", "iccid", state.ICCID)
			return nil
		}
	}
	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, cfg.eid, 1)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		logger.Info("demo operation already pending; not enqueueing another trigger")
		return nil
	}

	transactionID := demoTransactionID(cfg.eid, cfg.activationCode)
	trigger, err := profiledownload.NewActivationCodeTrigger(cfg.activationCode, transactionID)
	if err != nil {
		return err
	}
	operation, err := profiledownload.EnqueueTrigger(ctx, store, storage.DefaultTenantID, cfg.eid, trigger)
	if err != nil {
		return err
	}
	logger.Info("queued profile download trigger", "operation", operation.ID, "sequence", operation.SequenceNumber, "activationCode", cfg.activationCode)
	return nil
}

func demoTransactionID(eid, activationCode string) []byte {
	sum := sha256.Sum256([]byte(eid + "\x00" + activationCode))
	return sum[:16]
}

func statusHandler(ctx context.Context, store storage.Store, eid string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		states, err := store.ListProfileStates(ctx, storage.DefaultTenantID, eid)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"eid":      eid,
			"profiles": states,
		})
	}
}
