package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestCachedBundleProviderFallsBackToLastKnownGood(t *testing.T) {
	t.Parallel()

	provider := &stubBundleProvider{
		bundles: []*domain.TenantBundle{
			{
				TenantID: "tenant-1",
				Revision: "rev-1",
			},
		},
		err: errors.New("control plane unavailable"),
	}

	cache := NewCachedBundleProvider(provider, time.Millisecond, slog.Default())

	first, err := cache.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)
	require.Equal(t, "rev-1", first.Revision)

	time.Sleep(5 * time.Millisecond)

	second, err := cache.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "rev-1", second.Revision)
	assert.Equal(t, 2, provider.calls)

	status := cache.CheckStatus(context.Background())
	assert.Equal(t, "stale", status.Status)
	assert.Contains(t, status.Message, "last-known-good")
}

func TestCachedBundleProviderFailsClosedWithoutBundle(t *testing.T) {
	t.Parallel()

	cache := NewCachedBundleProvider(&stubBundleProvider{
		err: errors.New("control plane unavailable"),
	}, time.Second, slog.Default())

	_, err := cache.GetTenantBundle(context.Background(), "tenant-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrBundleUnavailable)

	status := cache.CheckStatus(context.Background())
	assert.Equal(t, "unavailable", status.Status)
	assert.Contains(t, status.Message, "no cached bundle available")
}

func TestCachedBundleProviderReportsIdleBeforeAnyTenantLoads(t *testing.T) {
	t.Parallel()

	cache := NewCachedBundleProvider(&stubBundleProvider{}, time.Second, slog.Default())

	status := cache.CheckStatus(context.Background())
	assert.Equal(t, "idle", status.Status)
	assert.Equal(t, "no tenant bundles loaded yet", status.Message)
}

func TestCachedBundleProviderReportsReadyAfterSuccessfulLoad(t *testing.T) {
	t.Parallel()

	cache := NewCachedBundleProvider(&stubBundleProvider{
		bundles: []*domain.TenantBundle{
			{
				TenantID: "tenant-1",
				Revision: "revision-1234567890abcdef",
			},
		},
	}, time.Second, slog.Default())

	_, err := cache.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)

	status := cache.CheckStatus(context.Background())
	assert.Equal(t, "ready", status.Status)
	assert.Contains(t, status.Message, "1 cached bundle")
	assert.Contains(t, status.Message, "revision-123")
}

func TestBundleServiceIncludesTenantRuntime(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	tenantRepo := &stubBundleTenantGetter{
		tenant: &domain.Tenant{
			ID:        "tenant-1",
			Name:      "Tenant One",
			CreatedAt: now.Add(-time.Hour),
			UpdatedAt: now,
		},
	}

	upstreamRepo := &stubBundleUpstreamRepo{
		bundleUpstreams: []domain.Upstream{{ID: "upstream-1", TenantID: "tenant-1", Name: "npmjs"}},
	}

	service, err := NewBundleService(
		tenantRepo,
		stubBundlePolicyRepo{
			policies: []domain.Policy{{ID: "policy-1", TenantID: "tenant-1", Name: "deny old"}},
		},
		upstreamRepo,
		WithBundleUpstreamRepository(upstreamRepo),
	)
	require.NoError(t, err)

	bundle, err := service.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, *tenantRepo.tenant, bundle.Tenant)
	assert.Equal(t, tenantRepo.tenant.ID, bundle.TenantID)
}

func TestBundleServiceRevisionChangesWhenTenantRuntimeChanges(t *testing.T) {
	t.Parallel()

	tenantRepo := &stubBundleTenantGetter{
		tenant: &domain.Tenant{ID: "tenant-1", Name: "Tenant One"},
	}

	upstreamRepo := &stubBundleUpstreamRepo{}
	service, err := NewBundleService(
		tenantRepo,
		stubBundlePolicyRepo{},
		upstreamRepo,
		WithBundleUpstreamRepository(upstreamRepo),
	)
	require.NoError(t, err)

	first, err := service.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)

	tenantRepo.tenant = &domain.Tenant{ID: "tenant-1", Name: "Tenant Renamed"}

	second, err := service.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.NotEqual(t, first.Revision, second.Revision)
}

func TestBundleRevisionTracksPolicyAndUpstreamScope(t *testing.T) {
	t.Parallel()

	tenant := domain.Tenant{ID: "tenant-1"}
	policyOne := domain.Policy{
		ID:             "policy-1",
		ScopeKind:      domain.PolicyScopeOrganization,
		OrganizationID: "organization-1",
	}
	policyTwo := policyOne
	policyTwo.OrganizationID = "organization-2"
	upstreamOne := domain.Upstream{
		ID:             "upstream-1",
		ScopeKind:      domain.UpstreamScopeTeamLocal,
		OrganizationID: "organization-1",
		TeamID:         "team-1",
	}
	upstreamTwo := upstreamOne
	upstreamTwo.TeamID = "team-2"

	first, err := bundleRevision(tenant, []domain.Policy{policyOne}, []domain.Upstream{upstreamOne})
	require.NoError(t, err)
	policyChanged, err := bundleRevision(tenant, []domain.Policy{policyTwo}, []domain.Upstream{upstreamOne})
	require.NoError(t, err)
	upstreamChanged, err := bundleRevision(tenant, []domain.Policy{policyOne}, []domain.Upstream{upstreamTwo})
	require.NoError(t, err)

	assert.NotEqual(t, first, policyChanged)
	assert.NotEqual(t, first, upstreamChanged)
}

func TestBundleServiceRejectsAuthenticatedUpstreamsWhenAuthDisabled(t *testing.T) {
	t.Parallel()

	upstreamRepo := &stubBundleUpstreamRepo{
		bundleUpstreams: []domain.Upstream{{
			ID:        "upstream-1",
			TenantID:  "tenant-1",
			Name:      "private-oci",
			Ecosystem: domain.EcosystemOCI,
			Auth: &domain.UpstreamAuth{
				Type:   domain.UpstreamAuthBearerToken,
				Secret: "registry-token",
			},
		}},
	}

	service, err := NewBundleService(
		&stubBundleTenantGetter{tenant: &domain.Tenant{ID: "tenant-1", Name: "Tenant One"}},
		stubBundlePolicyRepo{},
		upstreamRepo,
		WithBundleUpstreamAuth(false),
		WithBundleUpstreamRepository(upstreamRepo),
	)
	require.NoError(t, err)

	_, err = service.GetTenantBundle(context.Background(), "tenant-1")
	require.ErrorIs(t, err, domain.ErrUpstreamAuthTransportInsecure)
}

func TestNewBundleServiceRequiresBundleRepository(t *testing.T) {
	t.Parallel()

	_, err := NewBundleService(
		&stubBundleTenantGetter{tenant: &domain.Tenant{ID: "tenant-1", Name: "Tenant One"}},
		stubBundlePolicyRepo{},
		&stubBundleUpstreamRepo{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle upstream repository")
}

func TestNewBundleServiceRequiresBundleRepositoryWhenAuthDisabled(t *testing.T) {
	t.Parallel()

	_, err := NewBundleService(
		&stubBundleTenantGetter{tenant: &domain.Tenant{ID: "tenant-1", Name: "Tenant One"}},
		stubBundlePolicyRepo{},
		&stubBundleUpstreamRepo{},
		WithBundleUpstreamAuth(false),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle upstream repository")
}

func TestBundleServiceUsesBundleUpstreamRepository(t *testing.T) {
	t.Parallel()

	upstreamRepo := &stubBundleUpstreamRepo{
		panicOnListByTenant: true,
		bundleUpstreams: []domain.Upstream{{
			ID:       "upstream-1",
			TenantID: "tenant-1",
			Name:     "npmjs",
		}},
	}

	service, err := NewBundleService(
		&stubBundleTenantGetter{tenant: &domain.Tenant{ID: "tenant-1", Name: "Tenant One"}},
		stubBundlePolicyRepo{},
		upstreamRepo,
		WithBundleUpstreamRepository(upstreamRepo),
	)
	require.NoError(t, err)

	_, err = service.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.Zero(t, upstreamRepo.listByTenantCalls)
	assert.Equal(t, 1, upstreamRepo.listBundleByTenantCalls)
}

func TestBundleRevisionIgnoresUpstreamAuthSecretChanges(t *testing.T) {
	t.Parallel()

	tenant := domain.Tenant{ID: "tenant-1", Name: "Tenant One"}
	upstreamsOne := []domain.Upstream{{
		ID:        "upstream-1",
		TenantID:  "tenant-1",
		Name:      "private-oci",
		Ecosystem: domain.EcosystemOCI,
		Auth: &domain.UpstreamAuth{
			Type:   domain.UpstreamAuthBearerToken,
			Secret: "first-token",
		},
	}}
	upstreamsTwo := []domain.Upstream{{
		ID:        "upstream-1",
		TenantID:  "tenant-1",
		Name:      "private-oci",
		Ecosystem: domain.EcosystemOCI,
		Auth: &domain.UpstreamAuth{
			Type:   domain.UpstreamAuthBearerToken,
			Secret: "second-token",
		},
	}}

	first, err := bundleRevision(tenant, nil, upstreamsOne)
	require.NoError(t, err)
	second, err := bundleRevision(tenant, nil, upstreamsTwo)
	require.NoError(t, err)

	assert.Equal(t, first, second)
}

func TestBundleRevisionTracksUpstreamAuthUpdatedAt(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	tenant := domain.Tenant{ID: "tenant-1", Name: "Tenant One"}
	upstreamsOne := []domain.Upstream{{
		ID:        "upstream-1",
		TenantID:  "tenant-1",
		Name:      "private-oci",
		Ecosystem: domain.EcosystemOCI,
		Auth: &domain.UpstreamAuth{
			Type:      domain.UpstreamAuthBearerToken,
			UpdatedAt: now,
		},
	}}
	upstreamsTwo := []domain.Upstream{{
		ID:        "upstream-1",
		TenantID:  "tenant-1",
		Name:      "private-oci",
		Ecosystem: domain.EcosystemOCI,
		Auth: &domain.UpstreamAuth{
			Type:      domain.UpstreamAuthBearerToken,
			UpdatedAt: now.Add(time.Minute),
		},
	}}

	first, err := bundleRevision(tenant, nil, upstreamsOne)
	require.NoError(t, err)
	second, err := bundleRevision(tenant, nil, upstreamsTwo)
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
}

func TestBundleRevisionTracksPolicyTarget(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	tenant := domain.Tenant{ID: "tenant-1", Name: "Tenant One"}
	policiesOne := []domain.Policy{{
		ID:            "policy-1",
		TenantID:      "tenant-1",
		Name:          "targeted cvss",
		Type:          domain.PolicyTypeCVSSThreshold,
		Action:        domain.PolicyActionDeny,
		SchemaVersion: 1,
		Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: bundleTestFloat64Ptr(7)},
		Target: &domain.PolicyTarget{
			DependencyScopes: []domain.DependencyScope{domain.DependencyScopeDirect},
			OnUnknown:        domain.DependencyUnknownWarn,
		},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}}
	policiesTwo := []domain.Policy{{
		ID:            "policy-1",
		TenantID:      "tenant-1",
		Name:          "targeted cvss",
		Type:          domain.PolicyTypeCVSSThreshold,
		Action:        domain.PolicyActionDeny,
		SchemaVersion: 1,
		Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: bundleTestFloat64Ptr(7)},
		Target: &domain.PolicyTarget{
			DependencyScopes: []domain.DependencyScope{domain.DependencyScopeTransitive},
			OnUnknown:        domain.DependencyUnknownWarn,
		},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}}

	first, err := bundleRevision(tenant, policiesOne, nil)
	require.NoError(t, err)
	second, err := bundleRevision(tenant, policiesTwo, nil)
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
}

type stubBundleProvider struct {
	bundles []*domain.TenantBundle
	err     error
	calls   int
}

func (s *stubBundleProvider) GetTenantBundle(context.Context, string) (*domain.TenantBundle, error) {
	s.calls++
	if len(s.bundles) >= s.calls {
		return s.bundles[s.calls-1], nil
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.bundles[len(s.bundles)-1], nil
}

func bundleTestFloat64Ptr(value float64) *float64 {
	return &value
}

type stubBundleTenantGetter struct {
	tenant *domain.Tenant
	err    error
}

func (s *stubBundleTenantGetter) GetByID(context.Context, string) (*domain.Tenant, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.tenant, nil
}

type stubBundlePolicyRepo struct {
	policies []domain.Policy
	err      error
}

func (s stubBundlePolicyRepo) GetByID(context.Context, string, string) (*domain.Policy, error) {
	return nil, nil
}

func (s stubBundlePolicyRepo) ListByTenant(context.Context, string) ([]domain.Policy, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]domain.Policy(nil), s.policies...), nil
}

func (s stubBundlePolicyRepo) ListVersions(context.Context, string, string, int) ([]domain.PolicyVersion, error) {
	return nil, nil
}

func (s stubBundlePolicyRepo) RollbackToVersion(context.Context, string, string, int) (*domain.Policy, error) {
	return nil, nil
}

func (s stubBundlePolicyRepo) Create(context.Context, *domain.Policy) error {
	return nil
}

func (s stubBundlePolicyRepo) Update(context.Context, *domain.Policy) error {
	return nil
}

func (s stubBundlePolicyRepo) Delete(context.Context, string, string, bool) error {
	return nil
}

type stubBundleUpstreamRepo struct {
	upstreams               []domain.Upstream
	bundleUpstreams         []domain.Upstream
	err                     error
	bundleErr               error
	panicOnListByTenant     bool
	listByTenantCalls       int
	listBundleByTenantCalls int
}

func (s *stubBundleUpstreamRepo) GetByID(context.Context, string, string) (*domain.Upstream, error) {
	return nil, nil
}

func (s *stubBundleUpstreamRepo) GetByEcosystem(
	context.Context,
	string,
	domain.EcosystemType,
) (*domain.Upstream, error) {
	return nil, nil
}

func (s *stubBundleUpstreamRepo) ListByTenant(context.Context, string) ([]domain.Upstream, error) {
	s.listByTenantCalls++
	if s.panicOnListByTenant {
		panic("ListByTenant should not be called")
	}
	if s.err != nil {
		return nil, s.err
	}
	return append([]domain.Upstream(nil), s.upstreams...), nil
}

func (s *stubBundleUpstreamRepo) ListBundleByTenant(context.Context, string) ([]domain.Upstream, error) {
	s.listBundleByTenantCalls++
	if s.bundleErr != nil {
		return nil, s.bundleErr
	}
	return append([]domain.Upstream(nil), s.bundleUpstreams...), nil
}

func (s *stubBundleUpstreamRepo) Create(context.Context, *domain.Upstream) error {
	return nil
}

func (s *stubBundleUpstreamRepo) Update(context.Context, *domain.Upstream) error {
	return nil
}

func (s *stubBundleUpstreamRepo) Delete(context.Context, string, string) error {
	return nil
}
