package service

import (
	"context"
	"errors"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// PermissionCatalogVersion and its sibling constants enumerate the supported values.
const PermissionCatalogVersion = 1

var allPermissions = []domain.Permission{
	domain.PermissionAccountRead, domain.PermissionAccountManage, domain.PermissionAccountDelete,
	domain.PermissionMembersRead, domain.PermissionMembersInvite, domain.PermissionMembersManage,
	domain.PermissionOrganizationsRead, domain.PermissionOrganizationsCreate, domain.PermissionOrganizationsManage,
	domain.PermissionTeamsRead, domain.PermissionTeamsManage,
	domain.PermissionPoliciesRead, domain.PermissionPoliciesWrite, domain.PermissionPoliciesDelete,
	domain.PermissionWaiversRequest, domain.PermissionWaiversApprove,
	domain.PermissionUpstreamsRead, domain.PermissionUpstreamsWrite, domain.PermissionUpstreamsDelete,
	domain.PermissionCredentialsRead, domain.PermissionCredentialsWrite, domain.PermissionCredentialsRevoke,
	domain.PermissionEvaluationsRead, domain.PermissionDependencyGraphsRead, domain.PermissionAuditRead,
	domain.PermissionCacheInvalidate,
}

var tenantRolePermissions = map[domain.TenantRole]map[domain.Permission]struct{}{
	domain.TenantRoleOwner: permissionSet(allPermissions...),
	domain.TenantRoleAdmin: permissionSet(without(allPermissions, domain.PermissionAccountDelete)...),
	domain.TenantRoleMember: permissionSet(
		domain.PermissionAccountRead,
		domain.PermissionMembersRead,
	),
}

var organizationRolePermissions = map[domain.OrganizationRole]map[domain.Permission]struct{}{
	domain.OrganizationRoleAdmin: permissionSet(
		domain.PermissionOrganizationsRead, domain.PermissionOrganizationsManage,
		domain.PermissionTeamsRead, domain.PermissionTeamsManage,
		domain.PermissionPoliciesRead, domain.PermissionPoliciesWrite, domain.PermissionPoliciesDelete,
		domain.PermissionWaiversRequest, domain.PermissionWaiversApprove,
		domain.PermissionUpstreamsRead, domain.PermissionUpstreamsWrite, domain.PermissionUpstreamsDelete,
		domain.PermissionCredentialsRead, domain.PermissionCredentialsWrite, domain.PermissionCredentialsRevoke,
		domain.PermissionEvaluationsRead, domain.PermissionDependencyGraphsRead, domain.PermissionAuditRead,
		domain.PermissionCacheInvalidate,
	),
	domain.OrganizationRolePolicyManager: permissionSet(
		domain.PermissionOrganizationsRead, domain.PermissionTeamsRead,
		domain.PermissionPoliciesRead, domain.PermissionPoliciesWrite, domain.PermissionPoliciesDelete,
		domain.PermissionWaiversRequest, domain.PermissionWaiversApprove,
		domain.PermissionUpstreamsRead,
		domain.PermissionEvaluationsRead, domain.PermissionDependencyGraphsRead, domain.PermissionAuditRead,
		domain.PermissionCacheInvalidate,
	),
	domain.OrganizationRoleOperator: permissionSet(
		domain.PermissionOrganizationsRead, domain.PermissionTeamsRead,
		domain.PermissionPoliciesRead, domain.PermissionWaiversRequest,
		domain.PermissionUpstreamsRead,
		domain.PermissionCredentialsRead, domain.PermissionCredentialsWrite, domain.PermissionCredentialsRevoke,
		domain.PermissionEvaluationsRead, domain.PermissionDependencyGraphsRead, domain.PermissionAuditRead,
		domain.PermissionCacheInvalidate,
	),
	domain.OrganizationRoleViewer: permissionSet(
		domain.PermissionOrganizationsRead, domain.PermissionTeamsRead,
		domain.PermissionPoliciesRead, domain.PermissionUpstreamsRead,
		domain.PermissionEvaluationsRead, domain.PermissionDependencyGraphsRead,
	),
}

func permissionSet(permissions ...domain.Permission) map[domain.Permission]struct{} {
	result := make(map[domain.Permission]struct{}, len(permissions))
	for _, permission := range permissions {
		result[permission] = struct{}{}
	}
	return result
}

func without(permissions []domain.Permission, excluded domain.Permission) []domain.Permission {
	result := make([]domain.Permission, 0, len(permissions)-1)
	for _, permission := range permissions {
		if permission != excluded {
			result = append(result, permission)
		}
	}
	return result
}

// AuthorizationService models an authorization service.
type AuthorizationService struct {
	organizations authorizationOrganizationGetter
	memberships   authorizationMembershipGetter
	teams         authorizationTeamGetter
	teamMembers   authorizationTeamMembershipChecker
}

type authorizationOrganizationGetter interface {
	GetByID(ctx context.Context, tenantID, id string) (*domain.Organization, error)
}

type authorizationMembershipGetter interface {
	Get(ctx context.Context, tenantID, organizationID, principalID string) (*domain.OrganizationMembership, error)
}

type authorizationTeamGetter interface {
	GetByID(ctx context.Context, tenantID, organizationID, id string) (*domain.Team, error)
}

type authorizationTeamMembershipChecker interface {
	IsMember(ctx context.Context, tenantID, organizationID, teamID, principalID string) (bool, error)
}

// NewAuthorizationService constructs a new AuthorizationService.
func NewAuthorizationService(
	organizations authorizationOrganizationGetter,
	memberships authorizationMembershipGetter,
	teams authorizationTeamGetter,
	teamMembers authorizationTeamMembershipChecker,
) *AuthorizationService {
	return &AuthorizationService{
		organizations: organizations,
		memberships:   memberships,
		teams:         teams,
		teamMembers:   teamMembers,
	}
}

// Authorize checks whether a principal may perform an operation in the requested scope.
//
//nolint:gocognit,gocyclo,funlen // authorization branches by scope and role
func (s *AuthorizationService) Authorize(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	permission domain.Permission,
	scope domain.AuthorizationScope,
) error {
	if principal.Principal.ID == "" || principal.TenantID == "" {
		return deny(domain.AuthorizationDenialUnauthenticated)
	}
	if scope.TenantID == "" || scope.TenantID != principal.TenantID {
		return deny(domain.AuthorizationDenialTenantMismatch)
	}

	tenantAdministrator := principal.TenantRole == domain.TenantRoleOwner ||
		principal.TenantRole == domain.TenantRoleAdmin
	permissions := copyPermissions(tenantRolePermissions[principal.TenantRole])
	organizationAdministrator := false
	var organizationRole domain.OrganizationRole

	if scope.OrganizationID != "" {
		organization, err := s.organizations.GetByID(ctx, scope.TenantID, scope.OrganizationID)
		if errors.Is(err, domain.ErrOrganizationNotFound) {
			return deny(domain.AuthorizationDenialOrganizationNotFound)
		}
		if err != nil {
			return err
		}
		if organization.Status != domain.OrganizationStatusActive {
			return deny(domain.AuthorizationDenialOrganizationNotFound)
		}

		if tenantAdministrator {
			mergePermissions(permissions, organizationRolePermissions[domain.OrganizationRoleAdmin])
			organizationAdministrator = true
			organizationRole = domain.OrganizationRoleAdmin
		} else {
			membership, err := s.memberships.Get(ctx, scope.TenantID, scope.OrganizationID, principal.Principal.ID)
			if errors.Is(err, domain.ErrOrganizationMembershipNotFound) {
				return deny(domain.AuthorizationDenialOrganizationUnassigned)
			}
			if err != nil {
				return err
			}
			mergePermissions(permissions, organizationRolePermissions[membership.Role])
			organizationAdministrator = membership.Role == domain.OrganizationRoleAdmin
			organizationRole = membership.Role
		}
	}

	if scope.TeamID != "" {
		if scope.OrganizationID == "" {
			return deny(domain.AuthorizationDenialTeamNotFound)
		}
		team, err := s.teams.GetByID(ctx, scope.TenantID, scope.OrganizationID, scope.TeamID)
		if errors.Is(err, domain.ErrTeamNotFound) || (err == nil && team.ArchivedAt != nil) {
			return deny(domain.AuthorizationDenialTeamNotFound)
		}
		if err != nil {
			return err
		}
		if !tenantAdministrator && !organizationAdministrator {
			member, err := s.teamMembers.IsMember(
				ctx,
				scope.TenantID,
				scope.OrganizationID,
				scope.TeamID,
				principal.Principal.ID,
			)
			if err != nil {
				return err
			}
			if !member {
				return deny(domain.AuthorizationDenialTeamMembershipRequired)
			}
		}
	}

	if organizationRole == domain.OrganizationRoleOperator && scope.TeamID == "" &&
		(permission == domain.PermissionCredentialsWrite || permission == domain.PermissionCredentialsRevoke) {
		return deny(domain.AuthorizationDenialTeamMembershipRequired)
	}

	if _, ok := permissions[permission]; !ok {
		return deny(domain.AuthorizationDenialInsufficientPermission)
	}
	return nil
}

func copyPermissions(source map[domain.Permission]struct{}) map[domain.Permission]struct{} {
	result := make(map[domain.Permission]struct{}, len(source))
	mergePermissions(result, source)
	return result
}

func mergePermissions(target, source map[domain.Permission]struct{}) {
	for permission := range source {
		target[permission] = struct{}{}
	}
}

func deny(reason domain.AuthorizationDenialReason) error {
	return &domain.AuthorizationError{Reason: reason}
}

// PermissionsForTenantRole returns the permissions granted for the given role.
func PermissionsForTenantRole(role domain.TenantRole) []domain.Permission {
	return sortedPermissions(tenantRolePermissions[role])
}

// PermissionsForOrganizationRole returns the permissions granted for the given role.
func PermissionsForOrganizationRole(role domain.OrganizationRole) []domain.Permission {
	return sortedPermissions(organizationRolePermissions[role])
}

func sortedPermissions(set map[domain.Permission]struct{}) []domain.Permission {
	result := make([]domain.Permission, 0, len(set))
	for _, permission := range allPermissions {
		if _, ok := set[permission]; ok {
			result = append(result, permission)
		}
	}
	return result
}
