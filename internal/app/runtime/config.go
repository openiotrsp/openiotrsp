// Package runtime contains process-level helpers for demo binaries.
package runtime

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Env returns the trimmed environment value or fallback when unset.
func Env(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

// EnvBool returns a boolean environment value or fallback when unset/invalid.
func EnvBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

// EnvDuration returns a duration environment value or fallback when unset/invalid.
func EnvDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
