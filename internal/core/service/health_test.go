package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHealthChecker struct {
	err error
}

func (m *mockHealthChecker) Ping(_ context.Context) error {
	return m.err
}

func newTestHealthService(dbErr, cacheErr error) *HealthService {
	return NewHealthService(
		"test-service", "1.0.0", "abc123", "2024-01-01T00:00:00Z",
		&mockHealthChecker{err: dbErr},
		&mockHealthChecker{err: cacheErr},
		slog.Default(),
	)
}

func TestCheckHealth_AllHealthy(t *testing.T) {
	svc := newTestHealthService(nil, nil)
	resp := svc.CheckHealth(context.Background())

	assert.Equal(t, "healthy", resp.Status)
	assert.Equal(t, "test-service", resp.ServiceName)
	assert.Equal(t, "1.0.0", resp.Version)
	assert.Equal(t, "abc123", resp.Commit)
	assert.Equal(t, "2024-01-01T00:00:00Z", resp.BuildTime)
	assert.NotEmpty(t, resp.GoVersion)
	assert.NotEmpty(t, resp.OS)
	assert.NotEmpty(t, resp.Arch)
	assert.False(t, resp.Timestamp.IsZero())

	require.Len(t, resp.Dependencies, 2)
	assert.Equal(t, "healthy", resp.Dependencies["postgresql"].Status)
	assert.Empty(t, resp.Dependencies["postgresql"].Message)
	assert.Equal(t, "healthy", resp.Dependencies["valkey"].Status)
	assert.Empty(t, resp.Dependencies["valkey"].Message)
}

func TestCheckHealth_Degraded(t *testing.T) {
	svc := newTestHealthService(errors.New("connection refused"), nil)
	resp := svc.CheckHealth(context.Background())

	assert.Equal(t, "degraded", resp.Status)
	assert.Equal(t, "error", resp.Dependencies["postgresql"].Status)
	assert.Equal(t, "connection refused", resp.Dependencies["postgresql"].Message)
	assert.Equal(t, "healthy", resp.Dependencies["valkey"].Status)
}

func TestCheckHealth_DegradedCache(t *testing.T) {
	svc := newTestHealthService(nil, errors.New("cache down"))
	resp := svc.CheckHealth(context.Background())

	assert.Equal(t, "degraded", resp.Status)
	assert.Equal(t, "healthy", resp.Dependencies["postgresql"].Status)
	assert.Equal(t, "error", resp.Dependencies["valkey"].Status)
	assert.Equal(t, "cache down", resp.Dependencies["valkey"].Message)
}

func TestCheckHealth_AllFailed(t *testing.T) {
	svc := newTestHealthService(errors.New("db down"), errors.New("cache down"))
	resp := svc.CheckHealth(context.Background())

	assert.Equal(t, "error", resp.Status)
	assert.Equal(t, "error", resp.Dependencies["postgresql"].Status)
	assert.Equal(t, "error", resp.Dependencies["valkey"].Status)
}
