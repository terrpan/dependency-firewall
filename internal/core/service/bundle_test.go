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

	service := NewBundleService(
		tenantRepo,
		stubBundlePolicyRepo{
			policies: []domain.Policy{{ID: "policy-1", TenantID: "tenant-1", Name: "deny old"}},
		},
		stubBundleUpstreamRepo{
			upstreams: []domain.Upstream{{ID: "upstream-1", TenantID: "tenant-1", Name: "npmjs"}},
		},
	)

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

	service := NewBundleService(tenantRepo, stubBundlePolicyRepo{}, stubBundleUpstreamRepo{})

	first, err := service.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)

	tenantRepo.tenant = &domain.Tenant{ID: "tenant-1", Name: "Tenant Renamed"}

	second, err := service.GetTenantBundle(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.NotEqual(t, first.Revision, second.Revision)
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
	upstreams []domain.Upstream
	err       error
}

func (s stubBundleUpstreamRepo) GetByID(context.Context, string, string) (*domain.Upstream, error) {
	return nil, nil
}

func (s stubBundleUpstreamRepo) GetByEcosystem(context.Context, string, domain.EcosystemType) (*domain.Upstream, error) {
	return nil, nil
}

func (s stubBundleUpstreamRepo) ListByTenant(context.Context, string) ([]domain.Upstream, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]domain.Upstream(nil), s.upstreams...), nil
}

func (s stubBundleUpstreamRepo) Create(context.Context, *domain.Upstream) error {
	return nil
}

func (s stubBundleUpstreamRepo) Update(context.Context, *domain.Upstream) error {
	return nil
}

func (s stubBundleUpstreamRepo) Delete(context.Context, string, string) error {
	return nil
}
