package valkey

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestDecisionCache_InvalidateTenant(t *testing.T) {
	mini := miniredis.RunT(t)
	client, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress:  []string{mini.Addr()},
		DisableCache: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
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

	cached, err := cache.Get(ctx, "tenant-1", artifact, "")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, domain.DecisionAllow, cached.Outcome)

	require.NoError(t, cache.InvalidateTenant(ctx, "tenant-1"))

	_, err = cache.Get(ctx, "tenant-1", artifact, "")
	require.ErrorIs(t, err, domain.ErrCacheMiss)

	require.NoError(t, cache.Set(ctx, decision, time.Minute))

	cached, err = cache.Get(ctx, "tenant-1", artifact, "")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, domain.DecisionAllow, cached.Outcome)
}

func TestMetadataCache_InvalidateTenant(t *testing.T) {
	mini := miniredis.RunT(t)
	client, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress:  []string{mini.Addr()},
		DisableCache: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})

	cache := NewMetadataCache(client)
	ctx := context.Background()
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.20",
	}
	maxCVSS := 9.8
	metadata := &domain.ArtifactMetadata{MaxCVSS: &maxCVSS}

	require.NoError(t, cache.Set(ctx, "tenant-1", artifact, metadata, time.Minute))

	cached, err := cache.Get(ctx, "tenant-1", artifact)
	require.NoError(t, err)
	require.NotNil(t, cached)
	require.NotNil(t, cached.MaxCVSS)
	assert.InDelta(t, maxCVSS, *cached.MaxCVSS, 0.01)

	require.NoError(t, cache.InvalidateTenant(ctx, "tenant-1"))

	_, err = cache.Get(ctx, "tenant-1", artifact)
	require.ErrorIs(t, err, domain.ErrCacheMiss)
}
