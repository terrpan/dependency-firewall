package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type stubUpstreamRepository struct {
	created []domain.Upstream
	updated []domain.Upstream
}

func (s *stubUpstreamRepository) GetByID(context.Context, string, string) (*domain.Upstream, error) {
	return nil, domain.ErrUpstreamNotFound
}

func (s *stubUpstreamRepository) GetByEcosystem(
	context.Context,
	string,
	domain.EcosystemType,
) (*domain.Upstream, error) {
	return nil, domain.ErrUpstreamNotFound
}

func (s *stubUpstreamRepository) ListByTenant(context.Context, string) ([]domain.Upstream, error) {
	return nil, nil
}

func (s *stubUpstreamRepository) Create(_ context.Context, upstream *domain.Upstream) error {
	s.created = append(s.created, *upstream)
	return nil
}

func (s *stubUpstreamRepository) Update(_ context.Context, upstream *domain.Upstream) error {
	s.updated = append(s.updated, *upstream)
	return nil
}

func (s *stubUpstreamRepository) Delete(context.Context, string, string) error {
	return nil
}

type stubPolicyRepository struct {
	policies []domain.Policy
}

func (s *stubPolicyRepository) GetByID(context.Context, string, string) (*domain.Policy, error) {
	return nil, domain.ErrPolicyNotFound
}

func (s *stubPolicyRepository) ListByTenant(context.Context, string) ([]domain.Policy, error) {
	return append([]domain.Policy(nil), s.policies...), nil
}

func (s *stubPolicyRepository) ListVersions(context.Context, string, string, int) ([]domain.PolicyVersion, error) {
	return nil, domain.ErrPolicyNotFound
}

func (s *stubPolicyRepository) RollbackToVersion(context.Context, string, string, int) (*domain.Policy, error) {
	return nil, domain.ErrPolicyNotFound
}

func (s *stubPolicyRepository) Create(context.Context, *domain.Policy) error {
	return nil
}

func (s *stubPolicyRepository) Update(context.Context, *domain.Policy) error {
	return nil
}

func (s *stubPolicyRepository) Delete(context.Context, string, string, bool) error {
	return nil
}

func TestUpstreamService_CreateDefaultsCapabilities(t *testing.T) {
	repo := &stubUpstreamRepository{}
	service := NewUpstreamService(repo, nil)

	upstream := &domain.Upstream{
		TenantID:  "tenant-1",
		Name:      "npmjs",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	err := service.Create(context.Background(), upstream)

	require.NoError(t, err)
	require.Len(t, repo.created, 1)
	assert.Equal(t, domain.DefaultUpstreamCapabilities(domain.EcosystemNPM), upstream.Capabilities)
	assert.Equal(t, domain.DefaultUpstreamCapabilities(domain.EcosystemNPM), repo.created[0].Capabilities)
}

func TestUpstreamService_RejectsAuthenticatedUpstreamsWhenDisabled(t *testing.T) {
	repo := &stubUpstreamRepository{}
	service := NewUpstreamService(repo, nil, WithAuthenticatedUpstreams(false))

	err := service.Create(context.Background(), &domain.Upstream{
		TenantID:  "tenant-1",
		Name:      "private-oci",
		Ecosystem: domain.EcosystemOCI,
		BaseURL:   "https://ghcr.io",
		Auth: &domain.UpstreamAuth{
			Type:   domain.UpstreamAuthBearerToken,
			Secret: "registry-token",
		},
	})

	require.ErrorIs(t, err, domain.ErrUpstreamAuthTransportInsecure)
	assert.Empty(t, repo.created)
}

func TestUpstreamService_RejectsAuthForNonOCIUpstreams(t *testing.T) {
	repo := &stubUpstreamRepository{}
	service := NewUpstreamService(repo, nil)

	err := service.Create(context.Background(), &domain.Upstream{
		TenantID:  "tenant-1",
		Name:      "private-npm",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
		Auth: &domain.UpstreamAuth{
			Type:     domain.UpstreamAuthBasic,
			Username: "robot",
			Secret:   "secret",
		},
	})

	require.ErrorIs(t, err, domain.ErrUpstreamAuthInvalid)
	assert.Empty(t, repo.created)
}

func TestUpstreamService_UpdateRejectsIncompatibleScopedPolicies(t *testing.T) {
	repo := &stubUpstreamRepository{}
	policies := &stubPolicyRepository{
		policies: []domain.Policy{
			{
				ID:         "policy-1",
				TenantID:   "tenant-1",
				UpstreamID: "upstream-1",
				Name:       "block-licenses",
				Type:       domain.PolicyTypeLicense,
				Action:     domain.PolicyActionDeny,
				Config:     &domain.LicensePolicyConfig{Licenses: []string{"GPL-3.0-only"}},
				Enabled:    true,
			},
		},
	}
	service := NewUpstreamService(repo, policies)

	err := service.Update(context.Background(), &domain.Upstream{
		ID:           "upstream-1",
		TenantID:     "tenant-1",
		Name:         "npmjs",
		Ecosystem:    domain.EcosystemNPM,
		BaseURL:      "https://registry.npmjs.org",
		Capabilities: []domain.UpstreamCapability{domain.UpstreamCapabilityPublishTime},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrUpstreamPolicyConflict)
	assert.Contains(t, err.Error(), "block-licenses")
	assert.Empty(t, repo.updated)
}
