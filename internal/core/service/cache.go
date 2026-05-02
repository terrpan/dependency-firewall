package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// CacheService owns control-plane cache maintenance workflows.
type CacheService struct {
	decisionCache port.DecisionCache
	metadataCache port.MetadataCache
}

// NewCacheService creates a new CacheService.
func NewCacheService(decisionCache port.DecisionCache, metadataCache port.MetadataCache) *CacheService {
	return &CacheService{decisionCache: decisionCache, metadataCache: metadataCache}
}

// ClearTenantDecisions invalidates all cached decisions for a tenant.
func (s *CacheService) ClearTenantDecisions(ctx context.Context, tenantID string) error {
	if err := s.decisionCache.InvalidateTenant(ctx, tenantID); err != nil {
		return fmt.Errorf("clearing tenant decision cache: %w", err)
	}
	return nil
}

// ClearTenantMetadata invalidates all cached enrichment metadata for a tenant.
func (s *CacheService) ClearTenantMetadata(ctx context.Context, tenantID string) error {
	if err := s.metadataCache.InvalidateTenant(ctx, tenantID); err != nil {
		return fmt.Errorf("clearing tenant metadata cache: %w", err)
	}
	return nil
}
