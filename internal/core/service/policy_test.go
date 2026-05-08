package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type spyPolicyServiceRepo struct {
	createCalls     int
	updateCalls     int
	deleteCalls     int
	createErrAt     int
	deleteErr       error
	lastDeleteForce bool
	getPolicy       *domain.Policy
	listPolicies    []domain.Policy
	versions        map[string][]domain.PolicyVersion
}

func intPtr(v int) *int             { return &v }
func ptrFloat64(v float64) *float64 { return &v }

func importedPolicies(tenantID string) []domain.Policy {
	return []domain.Policy{
		{
			TenantID:      tenantID,
			Name:          "block-high",
			Type:          domain.PolicyTypeCVSSThreshold,
			Action:        domain.PolicyActionDeny,
			SchemaVersion: 1,
			Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.5)},
			Enabled:       true,
		},
		{
			TenantID:      tenantID,
			Name:          "block-old",
			Type:          domain.PolicyTypeMinimumAge,
			Action:        domain.PolicyActionDeny,
			SchemaVersion: 1,
			Config:        &domain.MinimumAgePolicyConfig{MinAgeDays: intPtr(30)},
			Priority:      1,
			Enabled:       true,
		},
	}
}

func (s *spyPolicyServiceRepo) Create(_ context.Context, policy *domain.Policy) error {
	s.createCalls++
	if s.createErrAt > 0 && s.createCalls == s.createErrAt {
		return errors.New("create failed")
	}
	copyPolicy := *policy
	if copyPolicy.ID == "" {
		copyPolicy.ID = fmt.Sprintf("policy-%d", s.createCalls)
		policy.ID = copyPolicy.ID
	}
	if copyPolicy.Version == 0 {
		copyPolicy.Version = 1
		policy.Version = 1
	}
	s.listPolicies = append(s.listPolicies, copyPolicy)
	s.recordVersion(copyPolicy)
	return nil
}

func (s *spyPolicyServiceRepo) GetByID(_ context.Context, tenantID, id string) (*domain.Policy, error) {
	if s.getPolicy != nil {
		copyPolicy := *s.getPolicy
		return &copyPolicy, nil
	}
	for i := range s.listPolicies {
		if s.listPolicies[i].TenantID == tenantID && s.listPolicies[i].ID == id {
			copyPolicy := s.listPolicies[i]
			return &copyPolicy, nil
		}
	}
	return nil, domain.ErrPolicyNotFound
}

func (s *spyPolicyServiceRepo) ListByTenant(context.Context, string) ([]domain.Policy, error) {
	return s.listPolicies, nil
}

func (s *spyPolicyServiceRepo) ListVersions(_ context.Context, tenantID, policyID string, limit int) ([]domain.PolicyVersion, error) {
	for i := range s.listPolicies {
		if s.listPolicies[i].TenantID == tenantID && s.listPolicies[i].ID == policyID {
			versions := append([]domain.PolicyVersion(nil), s.versions[policyID]...)
			if limit > 0 && len(versions) > limit {
				versions = versions[:limit]
			}
			return versions, nil
		}
	}
	return nil, domain.ErrPolicyNotFound
}

func (s *spyPolicyServiceRepo) Update(_ context.Context, policy *domain.Policy) error {
	s.updateCalls++
	for i := range s.listPolicies {
		if s.listPolicies[i].ID == policy.ID {
			policy.Version = s.listPolicies[i].Version + 1
			s.listPolicies[i] = *policy
			s.recordVersion(*policy)
			return nil
		}
	}
	s.listPolicies = append(s.listPolicies, *policy)
	s.recordVersion(*policy)
	return nil
}

func (s *spyPolicyServiceRepo) RollbackToVersion(_ context.Context, tenantID, policyID string, version int) (*domain.Policy, error) {
	for i := range s.listPolicies {
		if s.listPolicies[i].TenantID == tenantID && s.listPolicies[i].ID == policyID {
			var snapshot *domain.PolicyVersion
			for j := range s.versions[policyID] {
				if s.versions[policyID][j].Version == version {
					snapshot = &s.versions[policyID][j]
					break
				}
			}
			if snapshot == nil {
				return nil, domain.ErrPolicyVersionNotFound
			}
			s.listPolicies[i].Name = snapshot.Name
			s.listPolicies[i].Type = snapshot.Type
			s.listPolicies[i].Action = snapshot.Action
			s.listPolicies[i].SchemaVersion = snapshot.SchemaVersion
			s.listPolicies[i].Config = snapshot.Config
			s.listPolicies[i].Priority = snapshot.Priority
			s.listPolicies[i].Enabled = snapshot.Enabled
			s.listPolicies[i].Version++
			s.recordVersion(s.listPolicies[i])
			copyPolicy := s.listPolicies[i]
			return &copyPolicy, nil
		}
	}
	return nil, domain.ErrPolicyNotFound
}

func (s *spyPolicyServiceRepo) Delete(_ context.Context, _ string, id string, force bool) error {
	s.deleteCalls++
	s.lastDeleteForce = force
	if s.deleteErr != nil {
		return s.deleteErr
	}
	for i := range s.listPolicies {
		if s.listPolicies[i].ID == id {
			s.listPolicies = append(s.listPolicies[:i], s.listPolicies[i+1:]...)
			break
		}
	}
	return nil
}

func (s *spyPolicyServiceRepo) recordVersion(policy domain.Policy) {
	if s.versions == nil {
		s.versions = make(map[string][]domain.PolicyVersion)
	}
	version := domain.PolicyVersion{
		PolicyID:      policy.ID,
		Version:       policy.Version,
		Name:          policy.Name,
		Type:          policy.Type,
		Action:        policy.Action,
		SchemaVersion: policy.SchemaVersion,
		Config:        policy.Config,
		Priority:      policy.Priority,
		Enabled:       policy.Enabled,
		CreatedAt:     time.Now(),
	}
	history := append([]domain.PolicyVersion{version}, s.versions[policy.ID]...)
	if len(history) > domain.MaxRetainedPolicyVersions {
		history = history[:domain.MaxRetainedPolicyVersions]
	}
	s.versions[policy.ID] = history
}

type spyPolicyDecisionCache struct {
	invalidatedTenants []string
}

type spyPolicyRevisionRepository struct {
	revisions []domain.PolicySetRevision
}

type stubPolicyUpstreamRepository struct {
	upstreams map[string]domain.Upstream
}

func (s *stubPolicyUpstreamRepository) GetByID(_ context.Context, tenantID, id string) (*domain.Upstream, error) {
	upstream, ok := s.upstreams[tenantID+":"+id]
	if !ok {
		return nil, domain.ErrUpstreamNotFound
	}
	copyUpstream := upstream
	return &copyUpstream, nil
}

func (s *stubPolicyUpstreamRepository) GetByEcosystem(context.Context, string, domain.EcosystemType) (*domain.Upstream, error) {
	return nil, domain.ErrUpstreamNotFound
}

func (s *stubPolicyUpstreamRepository) ListByTenant(context.Context, string) ([]domain.Upstream, error) {
	return nil, nil
}

func (s *stubPolicyUpstreamRepository) Create(context.Context, *domain.Upstream) error {
	return nil
}

func (s *stubPolicyUpstreamRepository) Update(context.Context, *domain.Upstream) error {
	return nil
}

func (s *stubPolicyUpstreamRepository) Delete(context.Context, string, string) error {
	return nil
}

func (s *spyPolicyDecisionCache) Get(context.Context, string, domain.ArtifactIdentity) (*domain.Decision, error) {
	return nil, domain.ErrCacheMiss
}

func (s *spyPolicyDecisionCache) Set(context.Context, *domain.Decision, time.Duration) error {
	return nil
}

func (s *spyPolicyDecisionCache) Invalidate(context.Context, string, domain.ArtifactIdentity) error {
	return nil
}

func (s *spyPolicyDecisionCache) InvalidateTenant(_ context.Context, tenantID string) error {
	s.invalidatedTenants = append(s.invalidatedTenants, tenantID)
	return nil
}

func (s *spyPolicyRevisionRepository) Create(_ context.Context, revision *domain.PolicySetRevision) error {
	copyRevision := *revision
	copyRevision.Generation = int64(len(s.revisions) + 1)
	s.revisions = append(s.revisions, copyRevision)
	revision.Generation = copyRevision.Generation
	return nil
}

func TestPolicyService_MutationsInvalidateTenantDecisionCache(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Create(context.Background(), &domain.Policy{
			Name:     "warn-policy",
			TenantID: "tenant-1",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: intPtr(365), DryRun: true},
			Enabled:  true,
		})

		require.NoError(t, err)
		assert.Equal(t, 1, repo.createCalls)
		assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
		require.Len(t, revisions.revisions, 1)
		assert.NotEmpty(t, revisions.revisions[0].PolicyHash)
		cfg, ok := repo.listPolicies[0].Config.(*domain.MaximumAgePolicyConfig)
		require.True(t, ok)
		assert.True(t, cfg.DryRun)
	})

	t.Run("update", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Update(context.Background(), &domain.Policy{
			ID:       "policy-1",
			Name:     "warn-policy",
			TenantID: "tenant-1",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: intPtr(365), DryRun: true},
			Enabled:  true,
		})

		require.NoError(t, err)
		assert.Equal(t, 1, repo.updateCalls)
		assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
		require.Len(t, revisions.revisions, 1)
		assert.NotEmpty(t, revisions.revisions[0].PolicyHash)
		cfg, ok := repo.listPolicies[0].Config.(*domain.MaximumAgePolicyConfig)
		require.True(t, ok)
		assert.True(t, cfg.DryRun)
	})

	t.Run("delete", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		repo.listPolicies = []domain.Policy{
			{
				ID:       "policy-1",
				TenantID: "tenant-1",
				Name:     "existing",
				Type:     domain.PolicyTypeAllowlist,
				Action:   domain.PolicyActionAllow,
				Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
				Enabled:  false,
			},
		}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Delete(context.Background(), "tenant-1", "policy-1", false)

		require.NoError(t, err)
		assert.Equal(t, 1, repo.deleteCalls)
		assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
		require.Len(t, revisions.revisions, 1)
		assert.NotEmpty(t, revisions.revisions[0].PolicyHash)
	})

	t.Run("delete rejects enabled policy", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		repo.listPolicies = []domain.Policy{
			{
				ID:       "policy-1",
				TenantID: "tenant-1",
				Name:     "existing",
				Type:     domain.PolicyTypeAllowlist,
				Action:   domain.PolicyActionAllow,
				Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
				Enabled:  true,
			},
		}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Delete(context.Background(), "tenant-1", "policy-1", false)

		require.ErrorIs(t, err, domain.ErrPolicyDeleteEnabled)
		assert.Equal(t, 0, repo.deleteCalls)
		assert.Empty(t, cache.invalidatedTenants)
		assert.Empty(t, revisions.revisions)
	})

	t.Run("delete rejects referenced policy", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{
			deleteErr: domain.ErrPolicyInUse,
			listPolicies: []domain.Policy{
				{
					ID:       "policy-1",
					TenantID: "tenant-1",
					Name:     "existing",
					Type:     domain.PolicyTypeAllowlist,
					Action:   domain.PolicyActionAllow,
					Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
					Enabled:  false,
				},
			},
		}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Delete(context.Background(), "tenant-1", "policy-1", false)

		require.ErrorIs(t, err, domain.ErrPolicyInUse)
		assert.Equal(t, 1, repo.deleteCalls)
		assert.False(t, repo.lastDeleteForce)
		assert.Empty(t, cache.invalidatedTenants)
		assert.Empty(t, revisions.revisions)
	})

	t.Run("force delete passes flag to repo", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{
			listPolicies: []domain.Policy{
				{
					ID:       "policy-1",
					TenantID: "tenant-1",
					Name:     "existing",
					Type:     domain.PolicyTypeAllowlist,
					Action:   domain.PolicyActionAllow,
					Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
					Enabled:  false,
				},
			},
		}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Delete(context.Background(), "tenant-1", "policy-1", true)

		require.NoError(t, err)
		assert.True(t, repo.lastDeleteForce)
	})

	t.Run("import", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		count, err := service.ImportPolicies(context.Background(), "tenant-1", importedPolicies("tenant-1"))

		require.NoError(t, err)
		assert.Equal(t, 2, count)
		assert.Equal(t, 2, repo.createCalls)
		assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
		require.Len(t, revisions.revisions, 1)
		assert.NotEmpty(t, revisions.revisions[0].PolicyHash)
	})

	t.Run("import upserts by name", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{
			listPolicies: []domain.Policy{
				{
					ID:       "policy-1",
					TenantID: "tenant-1",
					Name:     "block-high",
					Type:     domain.PolicyTypeCVSSThreshold,
					Action:   domain.PolicyActionDeny,
					Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
					Priority: 0,
					Enabled:  true,
				},
			},
		}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		count, err := service.ImportPolicies(context.Background(), "tenant-1", []domain.Policy{
			{
				TenantID:      "different-tenant",
				Name:          "block-high",
				Type:          domain.PolicyTypeCVSSThreshold,
				Action:        domain.PolicyActionDeny,
				SchemaVersion: 1,
				Priority:      10,
				Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(9.5)},
				Enabled:       true,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, 1, count)
		assert.Zero(t, repo.createCalls)
		assert.Equal(t, 1, repo.updateCalls)
		require.Len(t, repo.listPolicies, 1)
		assert.Equal(t, "policy-1", repo.listPolicies[0].ID)
		assert.Equal(t, 10, repo.listPolicies[0].Priority)
		cfg, ok := repo.listPolicies[0].Config.(*domain.CVSSThresholdPolicyConfig)
		require.True(t, ok)
		require.NotNil(t, cfg.MaxCVSS)
		assert.Equal(t, 9.5, *cfg.MaxCVSS)
		assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
		require.Len(t, revisions.revisions, 1)
	})
}

func TestPolicyService_ListTypes(t *testing.T) {
	service := NewPolicyService(&spyPolicyServiceRepo{}, &spyPolicyRevisionRepository{}, &spyPolicyDecisionCache{}, nil)

	types := service.ListTypes()

	require.NotEmpty(t, types)
	assert.Equal(t, domain.PolicyTypeCVSSThreshold, types[0].Type)

	var foundAllowlist bool
	var foundNamespaceAllowlist bool
	for _, descriptor := range types {
		if descriptor.Type == domain.PolicyTypeLicenseAllowlist {
			foundAllowlist = true
			assert.NotEmpty(t, descriptor.Help)
			assert.NotEmpty(t, descriptor.Description)
			assert.Contains(t, descriptor.Example, "license_allowlist")
			assert.Equal(t, []domain.PolicyAction{domain.PolicyActionDeny}, descriptor.SupportedActions)
			assert.Equal(t, []domain.EcosystemType{domain.EcosystemNPM}, descriptor.SupportedEcosystems)
			assert.Equal(t, []domain.UpstreamCapability{domain.UpstreamCapabilityLicenses}, descriptor.RequiredCapabilities)
		}
		if descriptor.Type == domain.PolicyTypeNamespaceAllowlist {
			foundNamespaceAllowlist = true
			assert.NotEmpty(t, descriptor.Help)
			assert.NotEmpty(t, descriptor.Description)
			assert.Contains(t, descriptor.Example, "namespace_allowlist")
			assert.Equal(t, []domain.PolicyAction{domain.PolicyActionDeny}, descriptor.SupportedActions)
			assert.Equal(t, []domain.EcosystemType{domain.EcosystemNPM, domain.EcosystemOCI}, descriptor.SupportedEcosystems)
			assert.Empty(t, descriptor.RequiredCapabilities)
		}
	}
	assert.True(t, foundAllowlist)
	assert.True(t, foundNamespaceAllowlist)
}

func TestPolicyService_RejectsIncompatibleUpstreamCapabilities(t *testing.T) {
	repo := &spyPolicyServiceRepo{}
	revisions := &spyPolicyRevisionRepository{}
	cache := &spyPolicyDecisionCache{}
	upstreams := &stubPolicyUpstreamRepository{
		upstreams: map[string]domain.Upstream{
			"tenant-1:upstream-1": {
				ID:           "upstream-1",
				TenantID:     "tenant-1",
				Name:         "docker-hub",
				Ecosystem:    domain.EcosystemOCI,
				BaseURL:      "https://registry-1.docker.io",
				Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemOCI),
			},
		},
	}
	service := NewPolicyService(repo, revisions, cache, upstreams)

	err := service.Create(context.Background(), &domain.Policy{
		Name:          "license-check",
		TenantID:      "tenant-1",
		UpstreamID:    "upstream-1",
		Type:          domain.PolicyTypeLicense,
		Action:        domain.PolicyActionDeny,
		SchemaVersion: 1,
		Config:        &domain.LicensePolicyConfig{Licenses: []string{"MIT"}},
		Enabled:       true,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrPolicyUpstreamIncompatible)
	assert.Zero(t, repo.createCalls)
	assert.Empty(t, cache.invalidatedTenants)
	assert.Empty(t, revisions.revisions)
}

func TestPolicyService_ImportPolicies_InvalidatesAfterPartialMutationFailure(t *testing.T) {
	repo := &spyPolicyServiceRepo{createErrAt: 2}
	revisions := &spyPolicyRevisionRepository{}
	cache := &spyPolicyDecisionCache{}
	service := NewPolicyService(repo, revisions, cache, nil)

	count, err := service.ImportPolicies(context.Background(), "tenant-1", importedPolicies("tenant-1"))

	require.Error(t, err)
	assert.Zero(t, count)
	assert.Equal(t, 2, repo.createCalls)
	assert.Equal(t, []string{"tenant-1"}, cache.invalidatedTenants)
	require.Len(t, revisions.revisions, 1)
	assert.NotEmpty(t, revisions.revisions[0].PolicyHash)
	assert.Contains(t, err.Error(), "partial import")
}

func TestPolicyService_ImportPolicies_RejectsDuplicateNamesInDocument(t *testing.T) {
	repo := &spyPolicyServiceRepo{}
	revisions := &spyPolicyRevisionRepository{}
	cache := &spyPolicyDecisionCache{}
	service := NewPolicyService(repo, revisions, cache, nil)

	count, err := service.ImportPolicies(context.Background(), "tenant-1", []domain.Policy{
		{
			TenantID:      "tenant-1",
			Name:          "block-high",
			Type:          domain.PolicyTypeCVSSThreshold,
			Action:        domain.PolicyActionDeny,
			SchemaVersion: 1,
			Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.5)},
			Enabled:       true,
		},
		{
			TenantID:      "tenant-1",
			Name:          "block-high",
			Type:          domain.PolicyTypeMinimumAge,
			Action:        domain.PolicyActionDeny,
			SchemaVersion: 1,
			Config:        &domain.MinimumAgePolicyConfig{MinAgeDays: intPtr(30)},
			Priority:      1,
			Enabled:       true,
		},
	})

	require.Error(t, err)
	assert.Zero(t, count)
	assert.ErrorIs(t, err, domain.ErrInvalidPolicy)
	assert.Contains(t, err.Error(), "duplicate policy name")
	assert.Zero(t, repo.createCalls)
	assert.Zero(t, repo.updateCalls)
	assert.Empty(t, cache.invalidatedTenants)
	assert.Empty(t, revisions.revisions)
}

func TestPolicyService_RejectsDeprecatedEnforceConfig(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Create(context.Background(), &domain.Policy{
			Name:     "warn-policy",
			TenantID: "tenant-1",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
			Enabled:  true,
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrInvalidPolicy)
		assert.Zero(t, repo.createCalls)
		assert.Empty(t, cache.invalidatedTenants)
		assert.Empty(t, revisions.revisions)
	})

	t.Run("update", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		err := service.Update(context.Background(), &domain.Policy{
			ID:       "policy-1",
			Name:     "warn-policy",
			TenantID: "tenant-1",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
			Enabled:  true,
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrInvalidPolicy)
		assert.Zero(t, repo.updateCalls)
		assert.Empty(t, cache.invalidatedTenants)
		assert.Empty(t, revisions.revisions)
	})

	t.Run("import", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{}
		revisions := &spyPolicyRevisionRepository{}
		cache := &spyPolicyDecisionCache{}
		service := NewPolicyService(repo, revisions, cache, nil)

		count, err := service.ImportPolicies(context.Background(), "tenant-1", []domain.Policy{
			{
				TenantID:      "tenant-1",
				Name:          "block-high",
				Type:          domain.PolicyTypeCVSSThreshold,
				Action:        domain.PolicyActionDeny,
				SchemaVersion: 1,
				Config:        &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
				Enabled:       true,
			},
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrInvalidPolicy)
		assert.Zero(t, count)
		assert.Zero(t, repo.createCalls)
		assert.Empty(t, cache.invalidatedTenants)
		assert.Empty(t, revisions.revisions)
	})
}

func TestPolicyService_ValidatesLoadedPolicies(t *testing.T) {
	t.Run("get by id rejects invalid stored policy", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{
			getPolicy: &domain.Policy{
				ID:       "policy-1",
				TenantID: "tenant-1",
				Name:     "broken",
				Type:     domain.PolicyTypeCVSSThreshold,
				Action:   domain.PolicyActionDeny,
				Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
				Enabled:  true,
			},
		}
		service := NewPolicyService(repo, &spyPolicyRevisionRepository{}, &spyPolicyDecisionCache{}, nil)

		_, err := service.GetByID(context.Background(), "tenant-1", "policy-1")

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrInvalidPolicy)
	})

	t.Run("list rejects invalid stored policy", func(t *testing.T) {
		repo := &spyPolicyServiceRepo{
			listPolicies: []domain.Policy{
				{
					ID:       "policy-1",
					TenantID: "tenant-1",
					Name:     "broken",
					Type:     domain.PolicyTypeCVSSThreshold,
					Action:   domain.PolicyActionDeny,
					Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
					Enabled:  true,
				},
			},
		}
		service := NewPolicyService(repo, &spyPolicyRevisionRepository{}, &spyPolicyDecisionCache{}, nil)

		_, err := service.ListByTenant(context.Background(), "tenant-1")

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrInvalidPolicy)
	})
}
