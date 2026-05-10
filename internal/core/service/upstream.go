package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// UpstreamService owns upstream management workflows for the control plane.
type UpstreamService struct {
	repo                        port.UpstreamRepository
	policies                    port.PolicyRepository
	allowAuthenticatedUpstreams bool
}

// NewUpstreamService creates a new UpstreamService.
func NewUpstreamService(repo port.UpstreamRepository, policies port.PolicyRepository, options ...UpstreamServiceOption) *UpstreamService {
	s := &UpstreamService{
		repo:                        repo,
		policies:                    policies,
		allowAuthenticatedUpstreams: true,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// UpstreamServiceOption customizes upstream service behavior.
type UpstreamServiceOption func(*UpstreamService)

// WithAuthenticatedUpstreams controls whether the service may store authenticated upstream configs.
func WithAuthenticatedUpstreams(allowed bool) UpstreamServiceOption {
	return func(s *UpstreamService) {
		s.allowAuthenticatedUpstreams = allowed
	}
}

// Create creates an upstream.
func (s *UpstreamService) Create(ctx context.Context, upstream *domain.Upstream) error {
	capabilities, err := domain.NormalizeUpstreamCapabilities(upstream.Ecosystem, upstream.Capabilities)
	if err != nil {
		return err
	}
	upstream.Capabilities = capabilities
	if err := s.validateAuth(upstream); err != nil {
		return err
	}

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
	capabilities, err := domain.NormalizeUpstreamCapabilities(upstream.Ecosystem, upstream.Capabilities)
	if err != nil {
		return err
	}
	upstream.Capabilities = capabilities
	if err := s.validateAuth(upstream); err != nil {
		return err
	}

	if err := s.validateScopedPolicies(ctx, *upstream); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, upstream); err != nil {
		return fmt.Errorf("updating upstream: %w", err)
	}
	return nil
}

func (s *UpstreamService) validateAuth(upstream *domain.Upstream) error {
	if !upstream.UpstreamAuthConfigured() {
		return nil
	}
	if !s.allowAuthenticatedUpstreams {
		return domain.ErrUpstreamAuthTransportInsecure
	}
	if upstream.Ecosystem != domain.EcosystemOCI {
		return fmt.Errorf("%w: upstream auth is only supported for OCI", domain.ErrUpstreamAuthInvalid)
	}
	switch upstream.Auth.Type {
	case domain.UpstreamAuthBasic:
		if upstream.Auth.Username == "" || upstream.Auth.Secret == "" {
			return fmt.Errorf("%w: basic auth requires username and password", domain.ErrUpstreamAuthInvalid)
		}
	case domain.UpstreamAuthBearerToken:
		if upstream.Auth.Secret == "" {
			return fmt.Errorf("%w: bearer token auth requires token", domain.ErrUpstreamAuthInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported auth type %q", domain.ErrUpstreamAuthInvalid, upstream.Auth.Type)
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

func (s *UpstreamService) validateScopedPolicies(ctx context.Context, upstream domain.Upstream) error {
	if s.policies == nil {
		return nil
	}

	policies, err := s.policies.ListByTenant(ctx, upstream.TenantID)
	if err != nil {
		return fmt.Errorf("listing scoped policies for upstream update: %w", err)
	}
	for _, candidate := range policies {
		if candidate.UpstreamID != upstream.ID {
			continue
		}
		if err := policy.ValidateUpstreamCompatibility(candidate.Type, upstream); err != nil {
			return fmt.Errorf(
				"%w: upstream %q would no longer satisfy policy %q: %w",
				domain.ErrUpstreamPolicyConflict,
				upstream.Name,
				candidate.Name,
				err,
			)
		}
	}
	return nil
}
