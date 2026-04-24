package api

import (
	"context"
	"encoding/json"
	"errors"
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

func setupHealthServer(t *testing.T, dbErr, cacheErr error) *httptest.Server {
	t.Helper()
	healthSvc := service.NewHealthService(
		"test-firewall", "1.0.0", "abc123", "2024-01-01T00:00:00Z",
		&stubHealthChecker{err: dbErr},
		&stubHealthChecker{err: cacheErr},
		slog.Default(),
	)
	handler := NewHealthHandler(healthSvc, slog.Default())
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestHealthHandler_Healthy(t *testing.T) {
	srv := setupHealthServer(t, nil, nil)

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body healthResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "healthy", body.Status)
	assert.Equal(t, "test-firewall", body.ServiceName)
	assert.Len(t, body.Dependencies, 2)
	assert.Equal(t, "healthy", body.Dependencies["postgresql"].Status)
	assert.Equal(t, "healthy", body.Dependencies["valkey"].Status)
}

func TestHealthHandler_Degraded(t *testing.T) {
	srv := setupHealthServer(t, errors.New("db down"), nil)

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	var body healthResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "degraded", body.Status)
}

func TestHealthHandler_Error(t *testing.T) {
	srv := setupHealthServer(t, errors.New("db down"), errors.New("cache down"))

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	var body healthResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "error", body.Status)
	assert.Equal(t, "error", body.Dependencies["postgresql"].Status)
	assert.Equal(t, "error", body.Dependencies["valkey"].Status)
}

func TestHealthHandler_JSONStructure(t *testing.T) {
	srv := setupHealthServer(t, nil, nil)

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	var raw map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))

	expectedKeys := []string{"status", "service_name", "version", "go_version", "os", "arch", "timestamp", "dependencies"}
	for _, key := range expectedKeys {
		assert.Contains(t, raw, key, "response missing key: %s", key)
	}

	deps, ok := raw["dependencies"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, deps, "postgresql")
	assert.Contains(t, deps, "valkey")
}
