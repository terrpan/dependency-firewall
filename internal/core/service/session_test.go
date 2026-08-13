package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type sessionTenantFixture struct{ tenant *domain.Tenant }

func (f sessionTenantFixture) GetByID(_ context.Context, id string) (*domain.Tenant, error) {
	if f.tenant == nil || f.tenant.ID != id {
		return nil, domain.ErrTenantNotFound
	}
	tenant := *f.tenant
	return &tenant, nil
}

type sessionOrganizationFixture struct{ organizations []domain.Organization }

func (f sessionOrganizationFixture) ListByTenant(_ context.Context, tenantID string) ([]domain.Organization, error) {
	var organizations []domain.Organization
	for _, organization := range f.organizations {
		if organization.TenantID == tenantID {
			organizations = append(organizations, organization)
		}
	}
	return organizations, nil
}

func TestSessionService_CompatibilitySessionIsTenantScoped(t *testing.T) {
	tenant := &domain.Tenant{ID: "tenant-a", Name: "Account A"}
	service := NewSessionService(
		sessionTenantFixture{tenant: tenant},
		sessionOrganizationFixture{organizations: []domain.Organization{
			{ID: "org-active", TenantID: tenant.ID, Name: "Active", Status: domain.OrganizationStatusActive},
			{ID: "org-archived", TenantID: tenant.ID, Name: "Archived", Status: domain.OrganizationStatusArchived},
			{ID: "org-foreign", TenantID: "tenant-b", Name: "Foreign", Status: domain.OrganizationStatusActive},
		}},
	)

	session, err := service.CompatibilitySession(context.Background(), tenant.ID)
	require.NoError(t, err)
	assert.True(t, session.CompatibilityMode)
	assert.Equal(t, domain.TenantRoleOwner, session.TenantRole)
	require.Len(t, session.Organizations, 1)
	assert.Equal(t, "org-active", session.Organizations[0].Organization.ID)
	assert.Contains(t, session.AccountPermissions, domain.PermissionAccountDelete)
	assert.Contains(t, session.Organizations[0].Permissions, domain.PermissionPoliciesWrite)
}

func TestSessionService_CompatibilitySessionRequiresKnownTenant(t *testing.T) {
	service := NewSessionService(sessionTenantFixture{}, sessionOrganizationFixture{})
	_, err := service.CompatibilitySession(context.Background(), "missing")
	require.ErrorIs(t, err, domain.ErrTenantNotFound)
}
