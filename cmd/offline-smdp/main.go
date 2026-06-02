package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	appruntime "github.com/openiotrsp/openiotrsp/internal/app/runtime"
	"github.com/openiotrsp/openiotrsp/smdp/offline"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	addr := appruntime.Env("OPENIOTRSP_OFFLINE_SMDP_LISTEN_ADDR", ":8081")
	server := &http.Server{
		Addr:              addr,
		Handler:           offline.NewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Info("offline SM-DP+ stub listening", "addr", addr, "warning", "not signature proof")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("offline SM-DP+ stub stopped", "error", err)
		os.Exit(1)
	}
}
