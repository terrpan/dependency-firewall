package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type authorizationFixture struct {
	organization domain.Organization
	membership   *domain.OrganizationMembership
	team         domain.Team
	teamMember   bool
}

func (f *authorizationFixture) GetByID(_ context.Context, tenantID, id string) (*domain.Organization, error) {
	if tenantID != f.organization.TenantID || id != f.organization.ID {
		return nil, domain.ErrOrganizationNotFound
	}
	organization := f.organization
	return &organization, nil
}

func (f *authorizationFixture) Get(_ context.Context, tenantID, organizationID, principalID string) (*domain.OrganizationMembership, error) {
	if f.membership == nil || tenantID != f.membership.TenantID || organizationID != f.membership.OrganizationID || principalID != f.membership.PrincipalID {
		return nil, domain.ErrOrganizationMembershipNotFound
	}
	membership := *f.membership
	return &membership, nil
}

func (f *authorizationFixture) GetByIDTeam(_ context.Context, tenantID, organizationID, id string) (*domain.Team, error) {
	if tenantID != f.team.TenantID || organizationID != f.team.OrganizationID || id != f.team.ID {
		return nil, domain.ErrTeamNotFound
	}
	team := f.team
	return &team, nil
}

type teamRepositoryAdapter struct{ fixture *authorizationFixture }

func (a teamRepositoryAdapter) GetByID(ctx context.Context, tenantID, organizationID, id string) (*domain.Team, error) {
	return a.fixture.GetByIDTeam(ctx, tenantID, organizationID, id)
}

type teamMembershipAdapter struct{ fixture *authorizationFixture }

func (a teamMembershipAdapter) IsMember(context.Context, string, string, string, string) (bool, error) {
	return a.fixture.teamMember, nil
}

func TestAuthorizationService_RoleAndScopeMatrix(t *testing.T) {
	const (
		tenantID       = "tenant-a"
		organizationID = "organization-a"
		teamID         = "team-a"
		principalID    = "principal-a"
	)

	tests := []struct {
		name       string
		tenantRole domain.TenantRole
		orgRole    *domain.OrganizationRole
		teamMember bool
		permission domain.Permission
		scope      domain.AuthorizationScope
		wantReason domain.AuthorizationDenialReason
	}{
		{
			name:       "owner can delete account",
			tenantRole: domain.TenantRoleOwner,
			permission: domain.PermissionAccountDelete,
			scope:      domain.AuthorizationScope{TenantID: tenantID},
		},
		{
			name:       "admin cannot delete account",
			tenantRole: domain.TenantRoleAdmin,
			permission: domain.PermissionAccountDelete,
			scope:      domain.AuthorizationScope{TenantID: tenantID},
			wantReason: domain.AuthorizationDenialInsufficientPermission,
		},
		{
			name:       "tenant admin inherits organization administration",
			tenantRole: domain.TenantRoleAdmin,
			permission: domain.PermissionPoliciesWrite,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID},
		},
		{
			name:       "member requires organization assignment",
			tenantRole: domain.TenantRoleMember,
			permission: domain.PermissionPoliciesRead,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID},
			wantReason: domain.AuthorizationDenialOrganizationUnassigned,
		},
		{
			name:       "policy manager can approve organization waiver",
			tenantRole: domain.TenantRoleMember,
			orgRole:    rolePtr(domain.OrganizationRolePolicyManager),
			permission: domain.PermissionWaiversApprove,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID},
		},
		{
			name:       "viewer cannot read audit",
			tenantRole: domain.TenantRoleMember,
			orgRole:    rolePtr(domain.OrganizationRoleViewer),
			permission: domain.PermissionAuditRead,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID},
			wantReason: domain.AuthorizationDenialInsufficientPermission,
		},
		{
			name:       "operator needs team membership",
			tenantRole: domain.TenantRoleMember,
			orgRole:    rolePtr(domain.OrganizationRoleOperator),
			permission: domain.PermissionCredentialsWrite,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID, TeamID: teamID},
			wantReason: domain.AuthorizationDenialTeamMembershipRequired,
		},
		{
			name:       "operator cannot create organization credential",
			tenantRole: domain.TenantRoleMember,
			orgRole:    rolePtr(domain.OrganizationRoleOperator),
			permission: domain.PermissionCredentialsWrite,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID},
			wantReason: domain.AuthorizationDenialTeamMembershipRequired,
		},
		{
			name:       "operator can act in own team",
			tenantRole: domain.TenantRoleMember,
			orgRole:    rolePtr(domain.OrganizationRoleOperator),
			teamMember: true,
			permission: domain.PermissionCredentialsWrite,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID, TeamID: teamID},
		},
		{
			name:       "organization admin bypasses team membership",
			tenantRole: domain.TenantRoleMember,
			orgRole:    rolePtr(domain.OrganizationRoleAdmin),
			permission: domain.PermissionUpstreamsWrite,
			scope:      domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID, TeamID: teamID},
		},
		{
			name:       "tenant mismatch is hidden",
			tenantRole: domain.TenantRoleOwner,
			permission: domain.PermissionAccountRead,
			scope:      domain.AuthorizationScope{TenantID: "tenant-b"},
			wantReason: domain.AuthorizationDenialTenantMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := &authorizationFixture{
				organization: domain.Organization{ID: organizationID, TenantID: tenantID, Status: domain.OrganizationStatusActive},
				team:         domain.Team{ID: teamID, TenantID: tenantID, OrganizationID: organizationID},
				teamMember:   test.teamMember,
			}
			if test.orgRole != nil {
				fixture.membership = &domain.OrganizationMembership{
					TenantID: tenantID, OrganizationID: organizationID, PrincipalID: principalID, Role: *test.orgRole,
				}
			}
			service := NewAuthorizationService(fixture, fixture, teamRepositoryAdapter{fixture}, teamMembershipAdapter{fixture})
			principal := domain.AuthenticatedPrincipal{
				Principal:  domain.Principal{ID: principalID, Status: domain.PrincipalStatusActive},
				TenantID:   tenantID,
				TenantRole: test.tenantRole,
			}

			err := service.Authorize(context.Background(), principal, test.permission, test.scope)
			if test.wantReason == "" {
				require.NoError(t, err)
				return
			}
			var authError *domain.AuthorizationError
			require.ErrorAs(t, err, &authError)
			assert.Equal(t, test.wantReason, authError.Reason)
		})
	}
}

func TestAuthorizationService_ArchivedTeamIsHidden(t *testing.T) {
	archivedAt := time.Now()
	fixture := &authorizationFixture{
		organization: domain.Organization{ID: "org", TenantID: "tenant", Status: domain.OrganizationStatusActive},
		team:         domain.Team{ID: "team", TenantID: "tenant", OrganizationID: "org", ArchivedAt: &archivedAt},
	}
	service := NewAuthorizationService(fixture, fixture, teamRepositoryAdapter{fixture}, teamMembershipAdapter{fixture})
	err := service.Authorize(context.Background(), domain.AuthenticatedPrincipal{
		Principal: domain.Principal{ID: "principal"}, TenantID: "tenant", TenantRole: domain.TenantRoleAdmin,
	}, domain.PermissionTeamsRead, domain.AuthorizationScope{TenantID: "tenant", OrganizationID: "org", TeamID: "team"})

	var authError *domain.AuthorizationError
	require.ErrorAs(t, err, &authError)
	assert.Equal(t, domain.AuthorizationDenialTeamNotFound, authError.Reason)
}

func rolePtr(role domain.OrganizationRole) *domain.OrganizationRole { return &role }
