package runtime

import (
	"encoding/json"
	"net/http"
	"time"
)

// HealthHandler returns a small readiness response for compose health checks.
func HealthHandler(service string, started time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": service,
			"status":  "ok",
			"uptime":  time.Since(started).Truncate(time.Second).String(),
		})
	})
}
