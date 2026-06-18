package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	appruntime "github.com/openiotrsp/openiotrsp/internal/app/runtime"
	"github.com/openiotrsp/openiotrsp/mockipa"
	"github.com/openiotrsp/openiotrsp/pki"
)

type config struct {
	eimEndpoint  string
	eid          string
	mode         string
	fixtureZip   string
	imei         string
	statePath    string
	once         bool
	pollInterval time.Duration
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("mock IPA stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg := loadConfig()
	fixture, err := mockipa.LoadSGP26SoftwareFixture(cfg.fixtureZip)
	if err != nil {
		return err
	}
	eidHex := cfg.eid
	if eidHex == "" {
		eidHex = fixture.EID
	}
	if eidHex != fixture.EID {
		return fmt.Errorf(
			"OPENIOTRSP_DEMO_EID %q does not match SGP.26 fixture eUICC EID %q",
			eidHex,
			fixture.EID,
		)
	}
	eid, err := hex.DecodeString(eidHex)
	if err != nil {
		return fmt.Errorf("decode EID: %w", err)
	}
	transport, err := mockipa.NewTransportFromEndpoint(cfg.eimEndpoint, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	var stateStore *mockipa.StateStore
	if cfg.statePath != "" {
		stateStore, err = mockipa.OpenStateStore(cfg.statePath)
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := mockipa.Client{Transport: transport}
	runner := mockipa.Runner{
		Client:       client,
		Downloader:   downloader(cfg, client),
		Fixture:      fixture,
		StateStore:   stateStore,
		EID:          eid,
		PollInterval: cfg.pollInterval,
		Once:         cfg.once,
		Logger:       logger,
	}
	logger.Info(
		"mock IPA starting",
		"eid", eidHex,
		"mode", cfg.mode,
		"endpoint", cfg.eimEndpoint,
		"statePath", cfg.statePath,
		"eumCertBytes", len(fixture.EUMCertificate),
		"euiccCertBytes", len(fixture.EUICCCertificate),
	)
	return runner.Run(ctx)
}

func loadConfig() config {
	return config{
		eimEndpoint:  appruntime.Env("OPENIOTRSP_EIM_ESIPA_URL", "http://eim-server:8080/esipa"),
		eid:          appruntime.Env("OPENIOTRSP_DEMO_EID", pki.DefaultSGP26VariantONISTDemoEID),
		mode:         appruntime.Env("OPENIOTRSP_MOCKIPA_DOWNLOAD_MODE", "live"),
		fixtureZip:   appruntime.Env("OPENIOTRSP_SGP26_FIXTURE_ZIP", "spec/SGP.26_v3.0.2-17-July-2025.zip"),
		imei:         appruntime.Env("OPENIOTRSP_MOCKIPA_IMEI", "490154203237518"),
		statePath:    appruntime.Env("OPENIOTRSP_MOCKIPA_STATE_PATH", "/app/data/mockipa-state.json"),
		once:         appruntime.EnvBool("OPENIOTRSP_MOCKIPA_ONCE", true),
		pollInterval: appruntime.EnvDuration("OPENIOTRSP_MOCKIPA_POLL_INTERVAL", 2*time.Second),
	}
}

func downloader(cfg config, client mockipa.Client) mockipa.Downloader {
	switch strings.ToLower(strings.TrimSpace(cfg.mode)) {
	case "indirect":
		return mockipa.IndirectDownloader{
			Client:     client,
			FixtureZip: cfg.fixtureZip,
			IMEI:       cfg.imei,
		}
	default:
		return mockipa.SysmocomDownloader{
			FixtureZip: cfg.fixtureZip,
			IMEI:       cfg.imei,
		}
	}
}
