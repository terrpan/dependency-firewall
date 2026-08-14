package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

type bundleProvider interface {
	GetTenantBundle(ctx context.Context, tenantID string) (*domain.TenantBundle, error)
}

type credentialContextKey struct{}

// DataPlaneCredentialMiddleware authenticates npm bearer and OCI Basic
// credentials against digest-only verifiers carried in the local bundle.
type DataPlaneCredentialMiddleware struct{ bundles bundleProvider }

func NewDataPlaneCredentialMiddleware(bundles bundleProvider) *DataPlaneCredentialMiddleware {
	return &DataPlaneCredentialMiddleware{bundles: bundles}
}

func (m *DataPlaneCredentialMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
		if tenantID == "" {
			writeJSONError(w, "missing tenant route", http.StatusUnauthorized)
			return
		}
		bundle, err := m.bundles.GetTenantBundle(r.Context(), tenantID)
		if err != nil {
			writeJSONError(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(bundle.Credentials) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		secret, ok := presentedCredential(r)
		if !ok {
			writeJSONError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		for _, verifier := range bundle.Credentials {
			if verifier.TenantID != "" && verifier.TenantID != tenantID {
				continue
			}
			if service.VerifyCredentialSecret(secret, verifier, time.Now().UTC()) {
				ctx := context.WithValue(r.Context(), credentialContextKey{}, verifier)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		writeJSONError(w, "invalid credential", http.StatusUnauthorized)
	})
}

func presentedCredential(r *http.Request) (string, bool) {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		token := strings.TrimSpace(value[len("Bearer "):])
		return token, token != ""
	}
	if strings.HasPrefix(strings.ToLower(value), "basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len("Basic "):]))
		if err != nil {
			return "", false
		}
		_, password, ok := strings.Cut(string(decoded), ":")
		return password, ok && password != ""
	}
	return "", false
}

func CredentialFromContext(ctx context.Context) (domain.DataPlaneCredentialVerifier, bool) {
	v, ok := ctx.Value(credentialContextKey{}).(domain.DataPlaneCredentialVerifier)
	return v, ok
}
