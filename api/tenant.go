// Package api implements the stable northbound HTTP API consumed by decision
// engines, OEM systems, and enterprise products.
package api

import (
	"context"
	"net/http"

	"github.com/openiotrsp/openiotrsp/storage"
)

// TenantResolver maps an HTTP request to the tenant that owns the operation.
type TenantResolver interface {
	ResolveTenant(ctx context.Context, r *http.Request) (storage.TenantID, error)
}

// DefaultTenantResolver is the open source single-tenant resolver.
type DefaultTenantResolver struct{}

// ResolveTenant returns the open source default tenant.
func (DefaultTenantResolver) ResolveTenant(ctx context.Context, _ *http.Request) (storage.TenantID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return storage.DefaultTenantID, nil
}

// StaticTenantResolver is useful for tests and embedded single-tenant servers.
type StaticTenantResolver struct {
	TenantID storage.TenantID
}

// ResolveTenant returns the configured tenant, normalized to the open source default.
func (r StaticTenantResolver) ResolveTenant(ctx context.Context, _ *http.Request) (storage.TenantID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return storage.NormalizeTenantID(r.TenantID), nil
}
