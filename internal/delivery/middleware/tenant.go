// Package middleware provides HTTP middleware for the delivery layer.
package middleware

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

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

// NPMTenantFromPath is a middleware that extracts tenant ID from npm registry URLs.
// It supports the pattern /npm/t/{tenant-id}/{package...} and injects the tenant ID
// as X-Tenant-ID header so the standard TenantResolver middleware can handle it.
func NPMTenantFromPath() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path matches /npm/t/{tenant}/...
			if strings.HasPrefix(r.URL.Path, "/npm/t/") {
				parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/npm/t/"), "/", 2)
				if len(parts) >= 1 && parts[0] != "" {
					tenantID := parts[0]

					// Inject tenant ID as header for the TenantResolver middleware
					r.Header.Set("X-Tenant-ID", tenantID)

					// Rewrite path to /npm/{package...} for the handler
					if len(parts) == 2 {
						r.URL.Path = "/npm/" + parts[1]
					} else {
						r.URL.Path = "/npm/"
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// OCITenantFromHost extracts a tenant ID from the left-most hostname label for
// OCI requests and injects it as X-Tenant-ID when the request does not already
// provide the header directly.
func OCITenantFromHost() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Tenant-ID") == "" {
				if tenantID := tenantIDFromHost(r.Host); tenantID != "" {
					r.Header.Set("X-Tenant-ID", tenantID)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func tenantIDFromHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	}

	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return ""
	}

	labels := strings.Split(host, ".")
	if len(labels) < 2 || labels[0] == "" {
		return ""
	}

	return labels[0]
}

func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
