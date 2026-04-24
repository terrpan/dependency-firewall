package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// CacheService owns control-plane cache maintenance workflows.
type CacheService struct {
	decisionCache port.DecisionCache
}

// NewCacheService creates a new CacheService.
func NewCacheService(decisionCache port.DecisionCache) *CacheService {
	return &CacheService{decisionCache: decisionCache}
}

// ClearTenantDecisions invalidates all cached decisions for a tenant.
func (s *CacheService) ClearTenantDecisions(ctx context.Context, tenantID string) error {
	if err := s.decisionCache.InvalidateTenant(ctx, tenantID); err != nil {
		return fmt.Errorf("clearing tenant decision cache: %w", err)
	}
	return nil
}
