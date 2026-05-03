package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

type stubHealthChecker struct {
	err error
}

func (s *stubHealthChecker) Ping(_ context.Context) error {
	return s.err
}

type staticComponentChecker struct {
	status service.ComponentStatus
}

func (s staticComponentChecker) CheckStatus(context.Context) service.ComponentStatus {
	return s.status
}

func TestHandler_IncludesProxyStatusWhenConfigured(t *testing.T) {
	healthService := service.NewHealthService(
		"test-proxy",
		"1.0.0",
		"abc123",
		"2024-01-01T00:00:00Z",
		&stubHealthChecker{},
		&stubHealthChecker{},
		slog.Default(),
		service.WithProxyStatus("running", "proxy routes are served by this process"),
	)

	mux := http.NewServeMux()
	NewHandler(healthService).RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body healthResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.NotNil(t, body.Proxy)
	assert.Equal(t, "running", body.Proxy.Status)
	assert.Equal(t, "proxy routes are served by this process", body.Proxy.Message)
	assert.NotEmpty(t, body.Proxy.Timestamp)
}

func TestHandler_IncludesBundleStatusWhenConfigured(t *testing.T) {
	healthService := service.NewHealthService(
		"test-proxy",
		"1.0.0",
		"abc123",
		"2024-01-01T00:00:00Z",
		&stubHealthChecker{},
		&stubHealthChecker{},
		slog.Default(),
		service.WithBundleStatusChecker(staticComponentChecker{
			status: service.ComponentStatus{
				Status:  "ready",
				Message: "1 cached bundle",
			},
		}),
	)

	mux := http.NewServeMux()
	NewHandler(healthService).RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body healthResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.NotNil(t, body.Bundle)
	assert.Equal(t, "ready", body.Bundle.Status)
	assert.Equal(t, "1 cached bundle", body.Bundle.Message)
	assert.NotEmpty(t, body.Bundle.Timestamp)
}

func TestHandler_OmitsUnconfiguredDependencies(t *testing.T) {
	healthService := service.NewHealthService(
		"test-proxy",
		"1.0.0",
		"abc123",
		"2024-01-01T00:00:00Z",
		nil,
		&stubHealthChecker{},
		slog.Default(),
	)

	mux := http.NewServeMux()
	NewHandler(healthService).RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body healthResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.NotContains(t, body.Dependencies, "postgresql")
	assert.Equal(t, "healthy", body.Dependencies["valkey"].Status)
}
