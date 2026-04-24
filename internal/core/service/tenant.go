package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// TenantService owns tenant management workflows for the control plane.
type TenantService struct {
	repo port.TenantRepository
}

// NewTenantService creates a new TenantService.
func NewTenantService(repo port.TenantRepository) *TenantService {
	return &TenantService{repo: repo}
}

// Create creates a tenant.
func (s *TenantService) Create(ctx context.Context, tenant *domain.Tenant) error {
	if err := s.repo.Create(ctx, tenant); err != nil {
		return fmt.Errorf("creating tenant: %w", err)
	}
	return nil
}

// GetByID returns a tenant by ID.
func (s *TenantService) GetByID(ctx context.Context, id string) (*domain.Tenant, error) {
	tenant, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting tenant: %w", err)
	}
	return tenant, nil
}

// List returns all tenants.
func (s *TenantService) List(ctx context.Context) ([]domain.Tenant, error) {
	tenants, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	return tenants, nil
}

// Update updates a tenant.
func (s *TenantService) Update(ctx context.Context, tenant *domain.Tenant) error {
	if err := s.repo.Update(ctx, tenant); err != nil {
		return fmt.Errorf("updating tenant: %w", err)
	}
	return nil
}

// Delete removes a tenant by ID.
func (s *TenantService) Delete(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("deleting tenant: %w", err)
	}
	return nil
}
