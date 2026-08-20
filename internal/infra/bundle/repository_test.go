package bundle

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestUpstreamRepositoryGetByEcosystemRejectsAmbiguousFallback(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	repo := NewUpstreamRepository(staticProvider{
		bundle: &domain.TenantBundle{
			TenantID: "tenant-1",
			Upstreams: []domain.Upstream{
				{ID: "older", TenantID: "tenant-1", Ecosystem: domain.EcosystemNPM, UpdatedAt: now.Add(-time.Minute)},
				{ID: "newer", TenantID: "tenant-1", Ecosystem: domain.EcosystemNPM, UpdatedAt: now},
			},
		},
	})

	_, err := repo.GetByEcosystem(context.Background(), "tenant-1", domain.EcosystemNPM)
	require.ErrorIs(t, err, domain.ErrUpstreamAmbiguous)
}

func TestScopedBundleRepositoriesFilterVisibilityAndPolicyInheritance(t *testing.T) {
	t.Parallel()

	provider := staticProvider{bundle: &domain.TenantBundle{
		TenantID: "tenant-1",
		Policies: []domain.Policy{
			{ID: "account", TenantID: "tenant-1", ScopeKind: domain.PolicyScopeAccount},
			{
				ID:             "org-1",
				TenantID:       "tenant-1",
				ScopeKind:      domain.PolicyScopeOrganization,
				OrganizationID: "organization-1",
			},
			{
				ID:             "org-2",
				TenantID:       "tenant-1",
				ScopeKind:      domain.PolicyScopeOrganization,
				OrganizationID: "organization-2",
			},
		},
		Upstreams: []domain.Upstream{
			{ID: "tenant", TenantID: "tenant-1", ScopeKind: domain.UpstreamScopeTenantShared},
			{
				ID:             "org-1",
				TenantID:       "tenant-1",
				ScopeKind:      domain.UpstreamScopeOrganizationShared,
				OrganizationID: "organization-1",
			},
			{
				ID:             "team-1",
				TenantID:       "tenant-1",
				ScopeKind:      domain.UpstreamScopeTeamLocal,
				OrganizationID: "organization-1",
				TeamID:         "team-1",
			},
			{
				ID:             "team-2",
				TenantID:       "tenant-1",
				ScopeKind:      domain.UpstreamScopeTeamLocal,
				OrganizationID: "organization-1",
				TeamID:         "team-2",
			},
		},
	}}

	policyRepo := NewPolicyRepository(provider)
	policies, err := policyRepo.ListEffective(context.Background(), domain.AuthorizationScope{
		TenantID:       "tenant-1",
		OrganizationID: "organization-1",
	})
	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.ElementsMatch(t, []string{"account", "org-1"}, []string{policies[0].ID, policies[1].ID})

	upstreamRepo := NewUpstreamRepository(provider)
	upstreams, err := upstreamRepo.ListVisible(context.Background(), domain.AuthorizationScope{
		TenantID:       "tenant-1",
		OrganizationID: "organization-1",
		TeamID:         "team-1",
	})
	require.NoError(t, err)
	require.Len(t, upstreams, 3)
	assert.ElementsMatch(
		t,
		[]string{"tenant", "org-1", "team-1"},
		[]string{upstreams[0].ID, upstreams[1].ID, upstreams[2].ID},
	)
}

func TestPolicyRepositoryListByTenantReturnsBundlePolicies(t *testing.T) {
	t.Parallel()

	repo := NewPolicyRepository(staticProvider{
		bundle: &domain.TenantBundle{
			TenantID: "tenant-1",
			Policies: []domain.Policy{
				{ID: "policy-1", TenantID: "tenant-1", Name: "deny old"},
			},
		},
	})

	policies, err := repo.ListByTenant(context.Background(), "tenant-1")
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "policy-1", policies[0].ID)
}

func TestTenantLookupReturnsBundleTenantRuntime(t *testing.T) {
	t.Parallel()

	lookup := NewTenantLookup(staticProvider{
		bundle: &domain.TenantBundle{
			Tenant:   domain.Tenant{ID: "tenant-1", Name: "Tenant One"},
			TenantID: "tenant-1",
		},
	})

	tenant, err := lookup.GetByID(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", tenant.ID)
	assert.Equal(t, "Tenant One", tenant.Name)
}

func TestTenantLookupRejectsMismatchedBundleTenant(t *testing.T) {
	t.Parallel()

	lookup := NewTenantLookup(staticProvider{
		bundle: &domain.TenantBundle{
			Tenant:   domain.Tenant{ID: "other-tenant"},
			TenantID: "other-tenant",
		},
	})

	_, err := lookup.GetByID(context.Background(), "tenant-1")
	require.ErrorIs(t, err, domain.ErrTenantNotFound)
}

type staticProvider struct {
	bundle *domain.TenantBundle
}

func (p staticProvider) GetTenantBundle(context.Context, string) (*domain.TenantBundle, error) {
	return p.bundle, nil
}
