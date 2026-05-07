// runtime_test.go covers bootstrap-level runtime adapters that are not owned by lower layers.
package bootstrap

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestProxyHealthChecker_UsesProxyResponse(t *testing.T) {
	t.Parallel()

	timestamp := time.Date(2026, time.May, 3, 14, 42, 24, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"status":"healthy",
			"proxy":{"status":"running","message":"proxy routes are served by this process","timestamp":"2026-05-03T14:42:24Z"},
			"bundle":{"status":"ready","message":"1 cached bundle","timestamp":"2026-05-03T14:42:24Z"}
		}`))
	}))
	defer server.Close()

	checker := &proxyHealthChecker{
		url:    server.URL,
		client: server.Client(),
	}

	status := checker.CheckStatus(context.Background())

	assert.Equal(t, "running", status.Status)
	assert.Equal(t, "proxy routes are served by this process; bundle=ready", status.Message)
	assert.Equal(t, timestamp, status.Timestamp)
}

func TestRegisterProxyRoutes_UsesBundleBackedTenantLookup(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerProxyRoutes(
		mux,
		&dependencies{},
		slog.Default(),
		BuildInfo{},
		staticBundleProvider{
			bundle: &domain.TenantBundle{
				Tenant:   domain.Tenant{ID: "tenant-123", Name: "Tenant 123"},
				TenantID: "tenant-123",
			},
		},
		false,
	)

	req := httptest.NewRequest(http.MethodGet, "http://tenant-123.localhost/v2/", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

type staticBundleProvider struct {
	bundle *domain.TenantBundle
}

func (p staticBundleProvider) GetTenantBundle(context.Context, string) (*domain.TenantBundle, error) {
	return p.bundle, nil
}
