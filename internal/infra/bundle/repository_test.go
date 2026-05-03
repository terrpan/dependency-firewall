package bundle

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestUpstreamRepositoryGetByEcosystemSelectsMostRecent(t *testing.T) {
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

	upstream, err := repo.GetByEcosystem(context.Background(), "tenant-1", domain.EcosystemNPM)
	require.NoError(t, err)
	assert.Equal(t, "newer", upstream.ID)
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
