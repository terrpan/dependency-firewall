package valkey

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestDecisionCache_InvalidateTenant(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})

	cache := NewDecisionCache(client)
	ctx := context.Background()
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "express",
		Version:   "4.19.1",
	}
	decision := &domain.Decision{
		TenantID: "tenant-1",
		Artifact: artifact,
		Outcome:  domain.DecisionAllow,
	}

	require.NoError(t, cache.Set(ctx, decision, time.Minute))

	cached, err := cache.Get(ctx, "tenant-1", artifact)
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, domain.DecisionAllow, cached.Outcome)

	require.NoError(t, cache.InvalidateTenant(ctx, "tenant-1"))

	_, err = cache.Get(ctx, "tenant-1", artifact)
	require.ErrorIs(t, err, domain.ErrCacheMiss)

	require.NoError(t, cache.Set(ctx, decision, time.Minute))

	cached, err = cache.Get(ctx, "tenant-1", artifact)
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, domain.DecisionAllow, cached.Outcome)
}
