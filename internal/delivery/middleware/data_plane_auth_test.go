package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/require"
)

type bundleStub struct{ bundle *domain.TenantBundle }

func (b bundleStub) GetTenantBundle(context.Context, string) (*domain.TenantBundle, error) {
	return b.bundle, nil
}

func TestDataPlaneCredentialMiddlewareAcceptsBearerAndBasic(t *testing.T) {
	secret := "test-secret"
	hash := sha256.Sum256([]byte(secret))
	b := &domain.TenantBundle{Credentials: []domain.DataPlaneCredentialVerifier{{TenantID: "t", SecretDigest: hex.EncodeToString(hash[:])}}}
	h := NewDataPlaneCredentialMiddleware(bundleStub{bundle: b})
	for _, auth := range []string{"Bearer test-secret", "Basic dTpw"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Tenant-ID", "t")
		r.Header.Set("Authorization", auth)
		rr := httptest.NewRecorder()
		h.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rr, r)
		if auth == "Bearer test-secret" {
			require.Equal(t, http.StatusNoContent, rr.Code)
		} else {
			require.Equal(t, http.StatusUnauthorized, rr.Code)
		}
	}
}
