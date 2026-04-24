package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// UpstreamService owns upstream management workflows for the control plane.
type UpstreamService struct {
	repo port.UpstreamRepository
}

// NewUpstreamService creates a new UpstreamService.
func NewUpstreamService(repo port.UpstreamRepository) *UpstreamService {
	return &UpstreamService{repo: repo}
}

// Create creates an upstream.
func (s *UpstreamService) Create(ctx context.Context, upstream *domain.Upstream) error {
	if err := s.repo.Create(ctx, upstream); err != nil {
		return fmt.Errorf("creating upstream: %w", err)
	}
	return nil
}

// GetByID returns an upstream for a tenant.
func (s *UpstreamService) GetByID(ctx context.Context, tenantID, id string) (*domain.Upstream, error) {
	upstream, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("getting upstream: %w", err)
	}
	return upstream, nil
}

// ListByTenant returns upstreams for a tenant.
func (s *UpstreamService) ListByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error) {
	upstreams, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing upstreams: %w", err)
	}
	return upstreams, nil
}

// Update updates an upstream.
func (s *UpstreamService) Update(ctx context.Context, upstream *domain.Upstream) error {
	if err := s.repo.Update(ctx, upstream); err != nil {
		return fmt.Errorf("updating upstream: %w", err)
	}
	return nil
}

// Delete removes an upstream for a tenant.
func (s *UpstreamService) Delete(ctx context.Context, tenantID, id string) error {
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return fmt.Errorf("deleting upstream: %w", err)
	}
	return nil
}
