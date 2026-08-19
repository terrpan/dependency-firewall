package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type spyCacheDecisionCache struct {
	invalidatedTenants  []string
	invalidateTenantErr error
}

type spyCacheMetadataCache struct {
	invalidatedTenants  []string
	invalidateTenantErr error
}

func (s *spyCacheDecisionCache) Get(
	context.Context,
	string,
	domain.ArtifactIdentity,
	string,
) (*domain.Decision, error) {
	return nil, domain.ErrCacheMiss
}

func (s *spyCacheDecisionCache) Set(context.Context, *domain.Decision, time.Duration) error {
	return nil
}

func (s *spyCacheDecisionCache) Invalidate(context.Context, string, domain.ArtifactIdentity) error {
	return nil
}

func (s *spyCacheDecisionCache) InvalidateTenant(_ context.Context, tenantID string) error {
	if s.invalidateTenantErr != nil {
		return s.invalidateTenantErr
	}
	s.invalidatedTenants = append(s.invalidatedTenants, tenantID)
	return nil
}

func (s *spyCacheMetadataCache) Get(
	context.Context,
	string,
	domain.ArtifactIdentity,
) (*domain.ArtifactMetadata, error) {
	return nil, domain.ErrCacheMiss
}

func (s *spyCacheMetadataCache) Set(
	context.Context,
	string,
	domain.ArtifactIdentity,
	*domain.ArtifactMetadata,
	time.Duration,
) error {
	return nil
}

func (s *spyCacheMetadataCache) InvalidateTenant(_ context.Context, tenantID string) error {
	if s.invalidateTenantErr != nil {
		return s.invalidateTenantErr
	}
	s.invalidatedTenants = append(s.invalidatedTenants, tenantID)
	return nil
}

func TestCacheService_ClearTenantDecisions(t *testing.T) {
	cache := &spyCacheDecisionCache{}
	service := NewCacheService(cache, &spyCacheMetadataCache{})

	err := service.ClearTenantDecisions(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
}

func TestCacheService_ClearTenantDecisions_PropagatesErrors(t *testing.T) {
	cache := &spyCacheDecisionCache{invalidateTenantErr: errors.New("cache down")}
	service := NewCacheService(cache, &spyCacheMetadataCache{})

	err := service.ClearTenantDecisions(context.Background(), "tenant-1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "clearing tenant decision cache")
}

func TestCacheService_ClearTenantMetadata(t *testing.T) {
	cache := &spyCacheMetadataCache{}
	service := NewCacheService(&spyCacheDecisionCache{}, cache)

	err := service.ClearTenantMetadata(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
}

func TestCacheService_ClearTenantMetadata_PropagatesErrors(t *testing.T) {
	cache := &spyCacheMetadataCache{invalidateTenantErr: errors.New("cache down")}
	service := NewCacheService(&spyCacheDecisionCache{}, cache)

	err := service.ClearTenantMetadata(context.Background(), "tenant-1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "clearing tenant metadata cache")
}
