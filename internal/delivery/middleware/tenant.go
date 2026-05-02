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
const upstreamContextKey contextKey = "upstream"

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

// UpstreamIDFromContext retrieves the upstream ID from the request context.
func UpstreamIDFromContext(ctx context.Context) (string, bool) {
	upstreamID, ok := ctx.Value(upstreamContextKey).(string)
	return upstreamID, ok
}

// ContextWithUpstreamID returns a context with the given upstream ID set.
func ContextWithUpstreamID(ctx context.Context, upstreamID string) context.Context {
	return context.WithValue(ctx, upstreamContextKey, upstreamID)
}

// NPMTenantFromPath extracts tenant and optional upstream IDs from npm registry URLs.
// It supports:
//   - /npm/t/{tenant-id}/{package...}
//   - /npm/t/{tenant-id}/u/{upstream-id}/{package...}
//
// It injects the tenant ID as X-Tenant-ID and stores the optional upstream ID in
// the request context before rewriting the path to /npm/{package...}.
func NPMTenantFromPath() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/npm/t/") {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			tenantID, remainder, hasRemainder := strings.Cut(strings.TrimPrefix(r.URL.Path, "/npm/t/"), "/")
			if tenantID == "" {
				next.ServeHTTP(w, r)
				return
			}

			r.Header.Set("X-Tenant-ID", tenantID)

			packagePath := remainder
			if hasRemainder && strings.HasPrefix(remainder, "u/") {
				upstreamRemainder := strings.TrimPrefix(remainder, "u/")
				upstreamID, nextPath, _ := strings.Cut(upstreamRemainder, "/")
				if upstreamID != "" {
					ctx = ContextWithUpstreamID(ctx, upstreamID)
					packagePath = nextPath
				}
			}

			if packagePath != "" {
				r.URL.Path = "/npm/" + packagePath
			} else {
				r.URL.Path = "/npm/"
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OCITenantFromHost extracts tenant and optional upstream IDs from OCI hosts.
// It supports:
//   - {tenant-id}.{firewall-host}
//   - u-{upstream-id}.{tenant-id}.{firewall-host}
//
// The tenant ID is injected as X-Tenant-ID when the header is absent. The
// upstream ID is stored in request context when present.
func OCITenantFromHost() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			tenantID, upstreamID := tenantAndUpstreamIDFromHost(r.Host)
			if upstreamID != "" {
				ctx = ContextWithUpstreamID(ctx, upstreamID)
			}
			if r.Header.Get("X-Tenant-ID") == "" {
				if tenantID != "" {
					r.Header.Set("X-Tenant-ID", tenantID)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func tenantIDFromHost(host string) string {
	tenantID, _ := tenantAndUpstreamIDFromHost(host)
	return tenantID
}

func tenantAndUpstreamIDFromHost(host string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	}

	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return "", ""
	}

	labels := strings.Split(host, ".")
	if len(labels) < 2 || labels[0] == "" {
		return "", ""
	}

	if strings.HasPrefix(labels[0], "u-") && len(labels) >= 3 && labels[1] != "" {
		return labels[1], strings.TrimPrefix(labels[0], "u-")
	}

	return labels[0], ""
}

func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
