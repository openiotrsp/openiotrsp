// Package offline provides a CI-only SM-DP+ stub.
package offline

import (
	"encoding/json"
	"net/http"
	"time"
)

// NewHandler returns a tiny ES9+ shaped stub for offline CI plumbing.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"status": "ok",
			"mode":   "offline-stub-not-signature-proof",
		})
	})
	for _, path := range []string{
		"/gsma/rsp2/es9plus/initiateAuthentication",
		"/gsma/rsp2/es9plus/authenticateClient",
		"/gsma/rsp2/es9plus/getBoundProfilePackage",
		"/gsma/rsp2/es9plus/handleNotification",
		"/gsma/rsp2/es9plus/cancelSession",
	} {
		mux.HandleFunc(path, successResponse)
	}
	return mux
}

func successResponse(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"header": map[string]any{
			"functionExecutionStatus": map[string]string{
				"status": "Executed-Success",
			},
			"functionRequesterIdentifier": "openiotrsp-offline-stub",
			"functionCallIdentifier":      time.Now().UTC().Format("20060102150405"),
		},
		"offlineStubWarning": "CI fallback only; this response does not validate GSMA signatures",
	})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
