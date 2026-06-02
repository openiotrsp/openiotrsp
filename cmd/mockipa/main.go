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
)

const defaultEID = "89049032000000000000000000000001"

type config struct {
	eimEndpoint  string
	eid          string
	mode         string
	fixtureZip   string
	imei         string
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
	eid, err := hex.DecodeString(cfg.eid)
	if err != nil {
		return fmt.Errorf("decode EID: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runner := mockipa.Runner{
		Client: mockipa.Client{
			Endpoint:   cfg.eimEndpoint,
			HTTPClient: &http.Client{Timeout: 30 * time.Second},
		},
		Downloader:   downloader(cfg),
		EID:          eid,
		PollInterval: cfg.pollInterval,
		Once:         cfg.once,
		Logger:       logger,
	}
	logger.Info("mock IPA starting", "eid", cfg.eid, "mode", cfg.mode, "endpoint", cfg.eimEndpoint)
	return runner.Run(ctx)
}

func loadConfig() config {
	return config{
		eimEndpoint:  appruntime.Env("OPENIOTRSP_EIM_ESIPA_URL", "http://eim-server:8080/esipa"),
		eid:          appruntime.Env("OPENIOTRSP_DEMO_EID", defaultEID),
		mode:         appruntime.Env("OPENIOTRSP_MOCKIPA_DOWNLOAD_MODE", "live"),
		fixtureZip:   appruntime.Env("OPENIOTRSP_SGP26_FIXTURE_ZIP", "spec/SGP.26_v3.0.2-17-July-2025.zip"),
		imei:         appruntime.Env("OPENIOTRSP_MOCKIPA_IMEI", "490154203237518"),
		once:         appruntime.EnvBool("OPENIOTRSP_MOCKIPA_ONCE", true),
		pollInterval: appruntime.EnvDuration("OPENIOTRSP_MOCKIPA_POLL_INTERVAL", 2*time.Second),
	}
}

func downloader(cfg config) mockipa.Downloader {
	switch strings.ToLower(strings.TrimSpace(cfg.mode)) {
	case "offline", "offline-stub", "stub":
		return mockipa.OfflineDownloader{}
	default:
		return mockipa.SysmocomDownloader{
			FixtureZip: cfg.fixtureZip,
			IMEI:       cfg.imei,
		}
	}
}
