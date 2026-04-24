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

func (s *spyCacheDecisionCache) Get(context.Context, string, domain.ArtifactIdentity) (*domain.Decision, error) {
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

func TestCacheService_ClearTenantDecisions(t *testing.T) {
	cache := &spyCacheDecisionCache{}
	service := NewCacheService(cache)

	err := service.ClearTenantDecisions(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
}

func TestCacheService_ClearTenantDecisions_PropagatesErrors(t *testing.T) {
	cache := &spyCacheDecisionCache{invalidateTenantErr: errors.New("cache down")}
	service := NewCacheService(cache)

	err := service.ClearTenantDecisions(context.Background(), "tenant-1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "clearing tenant decision cache")
}
