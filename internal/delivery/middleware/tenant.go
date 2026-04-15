// Package middleware provides HTTP middleware for the delivery layer.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

type contextKey string

const tenantContextKey contextKey = "tenant"

// TenantResolver extracts tenant ID from requests and adds it to context.
type TenantResolver struct {
	tenantRepo port.TenantRepository
}

// NewTenantResolver creates a new TenantResolver.
func NewTenantResolver(repo port.TenantRepository) *TenantResolver {
	return &TenantResolver{tenantRepo: repo}
}

// Middleware returns an HTTP middleware that resolves the tenant from the request.
func (tr *TenantResolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			writeJSONError(w, "missing X-Tenant-ID header", http.StatusUnauthorized)
			return
		}

		tenant, err := tr.tenantRepo.GetByID(r.Context(), tenantID)
		if err != nil {
			writeJSONError(w, "invalid tenant", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), tenantContextKey, *tenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TenantFromContext retrieves the tenant from the request context.
func TenantFromContext(ctx context.Context) (domain.Tenant, bool) {
	t, ok := ctx.Value(tenantContextKey).(domain.Tenant)
	return t, ok
}

// ContextWithTenant returns a context with the given tenant set.
// This is used by tests and any code that needs to inject a tenant
// without going through the HTTP middleware.
func ContextWithTenant(ctx context.Context, tenant domain.Tenant) context.Context {
	return context.WithValue(ctx, tenantContextKey, tenant)
}

func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
