package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

type OrganizationAccess struct {
	Organization domain.Organization
	Role         domain.OrganizationRole
}

// HierarchyService owns local Organization, Team, and membership workflows.
// Tenant membership remains external; these assignments only narrow local scope.
type HierarchyService struct {
	organizations port.OrganizationRepository
	orgMembers    port.OrganizationMembershipRepository
	teams         port.TeamRepository
	teamMembers   port.TeamMembershipRepository
	principals    port.PrincipalRepository
	authorization *AuthorizationService
	membership    TenantMembershipVerifier
}

type TenantMembershipVerifier interface {
	VerifyTenantMembership(ctx context.Context, provider, externalAccountID, externalSubject string) error
}

func NewHierarchyService(
	organizations port.OrganizationRepository,
	orgMembers port.OrganizationMembershipRepository,
	teams port.TeamRepository,
	teamMembers port.TeamMembershipRepository,
	principals port.PrincipalRepository,
	authorization *AuthorizationService,
	membership ...TenantMembershipVerifier,
) *HierarchyService {
	service := &HierarchyService{organizations: organizations, orgMembers: orgMembers, teams: teams, teamMembers: teamMembers, principals: principals, authorization: authorization}
	if len(membership) > 0 {
		service.membership = membership[0]
	}
	return service
}

func (s *HierarchyService) ListOrganizations(ctx context.Context, principal domain.AuthenticatedPrincipal) ([]OrganizationAccess, error) {
	if tenantAdministrator(principal) {
		organizations, err := s.organizations.ListByTenant(ctx, principal.TenantID)
		if err != nil {
			return nil, fmt.Errorf("listing organizations: %w", err)
		}
		result := make([]OrganizationAccess, 0, len(organizations))
		for _, organization := range organizations {
			result = append(result, OrganizationAccess{Organization: organization, Role: domain.OrganizationRoleAdmin})
		}
		return result, nil
	}
	memberships, err := s.orgMembers.ListByPrincipal(ctx, principal.TenantID, principal.Principal.ID)
	if err != nil {
		return nil, fmt.Errorf("listing organization memberships: %w", err)
	}
	result := make([]OrganizationAccess, 0, len(memberships))
	for _, membership := range memberships {
		organization, err := s.organizations.GetByID(ctx, principal.TenantID, membership.OrganizationID)
		if errors.Is(err, domain.ErrOrganizationNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("loading assigned organization: %w", err)
		}
		result = append(result, OrganizationAccess{Organization: *organization, Role: membership.Role})
	}
	return result, nil
}

func (s *HierarchyService) CreateOrganization(ctx context.Context, principal domain.AuthenticatedPrincipal, name string) (*domain.Organization, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionOrganizationsCreate, domain.AuthorizationScope{TenantID: principal.TenantID}); err != nil {
		return nil, err
	}
	organization := &domain.Organization{TenantID: principal.TenantID, Name: name, Status: domain.OrganizationStatusActive}
	if err := s.organizations.Create(ctx, organization); err != nil {
		return nil, fmt.Errorf("creating organization: %w", err)
	}
	return organization, nil
}

func (s *HierarchyService) GetOrganization(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID string) (*OrganizationAccess, error) {
	scope := domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}
	if tenantAdministrator(principal) {
		scope.OrganizationID = ""
	}
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionOrganizationsRead, scope); err != nil {
		return nil, err
	}
	organization, err := s.organizations.GetByID(ctx, principal.TenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("getting organization: %w", err)
	}
	role := domain.OrganizationRoleAdmin
	if !tenantAdministrator(principal) {
		membership, err := s.orgMembers.Get(ctx, principal.TenantID, organizationID, principal.Principal.ID)
		if err != nil {
			return nil, fmt.Errorf("getting organization role: %w", err)
		}
		role = membership.Role
	}
	return &OrganizationAccess{Organization: *organization, Role: role}, nil
}

func (s *HierarchyService) UpdateOrganization(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, name string, status domain.OrganizationStatus) (*domain.Organization, error) {
	scope := domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}
	if tenantAdministrator(principal) {
		scope.OrganizationID = ""
	}
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionOrganizationsManage, scope); err != nil {
		return nil, err
	}
	organization, err := s.organizations.GetByID(ctx, principal.TenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("getting organization for update: %w", err)
	}
	organization.Name = name
	organization.Status = status
	if err := s.organizations.Update(ctx, organization); err != nil {
		return nil, fmt.Errorf("updating organization: %w", err)
	}
	return organization, nil
}

func (s *HierarchyService) GetOrganizationMembership(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, principalID string) (*domain.OrganizationMembership, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionOrganizationsRead, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	membership, err := s.orgMembers.Get(ctx, principal.TenantID, organizationID, principalID)
	if err != nil {
		return nil, fmt.Errorf("getting organization membership: %w", err)
	}
	return membership, nil
}

func (s *HierarchyService) SetOrganizationMembership(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, principalID string, role domain.OrganizationRole) (*domain.OrganizationMembership, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionOrganizationsManage, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if err := s.requireAssignablePrincipal(ctx, principal, principalID); err != nil {
		return nil, err
	}
	membership := &domain.OrganizationMembership{TenantID: principal.TenantID, OrganizationID: organizationID, PrincipalID: principalID, Role: role}
	if err := s.orgMembers.Upsert(ctx, membership); err != nil {
		return nil, fmt.Errorf("setting organization membership: %w", err)
	}
	return membership, nil
}

func (s *HierarchyService) ListTeams(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID string) ([]domain.Team, error) {
	scope := domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionTeamsRead, scope); err != nil {
		return nil, err
	}
	teams, err := s.teams.ListByOrganization(ctx, principal.TenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("listing teams: %w", err)
	}
	if tenantAdministrator(principal) {
		return teams, nil
	}
	membership, err := s.orgMembers.Get(ctx, principal.TenantID, organizationID, principal.Principal.ID)
	if err != nil {
		return nil, fmt.Errorf("getting organization membership: %w", err)
	}
	if membership.Role == domain.OrganizationRoleAdmin {
		return teams, nil
	}
	assigned, err := s.teamMembers.ListByPrincipal(ctx, principal.TenantID, organizationID, principal.Principal.ID)
	if err != nil {
		return nil, fmt.Errorf("listing team memberships: %w", err)
	}
	allowed := make(map[string]struct{}, len(assigned))
	for _, item := range assigned {
		allowed[item.TeamID] = struct{}{}
	}
	filtered := make([]domain.Team, 0, len(assigned))
	for _, team := range teams {
		if _, ok := allowed[team.ID]; ok {
			filtered = append(filtered, team)
		}
	}
	return filtered, nil
}

func (s *HierarchyService) CreateTeam(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, name string) (*domain.Team, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionTeamsManage, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	team := &domain.Team{TenantID: principal.TenantID, OrganizationID: organizationID, Name: name}
	if err := s.teams.Create(ctx, team); err != nil {
		return nil, fmt.Errorf("creating team: %w", err)
	}
	return team, nil
}

func (s *HierarchyService) GetTeam(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, teamID string) (*domain.Team, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionTeamsRead, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID, TeamID: teamID}); err != nil {
		return nil, err
	}
	team, err := s.teams.GetByID(ctx, principal.TenantID, organizationID, teamID)
	if err != nil {
		return nil, fmt.Errorf("getting team: %w", err)
	}
	return team, nil
}

func (s *HierarchyService) UpdateTeam(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, teamID, name string, archived bool) (*domain.Team, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionTeamsManage, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	team, err := s.teams.GetByID(ctx, principal.TenantID, organizationID, teamID)
	if err != nil {
		return nil, fmt.Errorf("getting team for update: %w", err)
	}
	team.Name = name
	if archived && team.ArchivedAt == nil {
		now := time.Now().UTC()
		team.ArchivedAt = &now
	} else if !archived {
		team.ArchivedAt = nil
	}
	if err := s.teams.Update(ctx, team); err != nil {
		return nil, fmt.Errorf("updating team: %w", err)
	}
	return team, nil
}

func (s *HierarchyService) IsTeamMember(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, teamID, principalID string) (bool, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionTeamsRead, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID, TeamID: teamID}); err != nil {
		return false, err
	}
	member, err := s.teamMembers.IsMember(ctx, principal.TenantID, organizationID, teamID, principalID)
	if err != nil {
		return false, fmt.Errorf("getting team membership: %w", err)
	}
	return member, nil
}

func (s *HierarchyService) SetTeamMembership(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, teamID, principalID string) (*domain.TeamMembership, error) {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionTeamsManage, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	team, err := s.teams.GetByID(ctx, principal.TenantID, organizationID, teamID)
	if err != nil || team.ArchivedAt != nil {
		if err == nil {
			err = domain.ErrTeamNotFound
		}
		return nil, fmt.Errorf("getting team for membership: %w", err)
	}
	if err := s.requireAssignablePrincipal(ctx, principal, principalID); err != nil {
		return nil, err
	}
	membership := &domain.TeamMembership{TenantID: principal.TenantID, OrganizationID: organizationID, TeamID: teamID, PrincipalID: principalID}
	if err := s.teamMembers.Upsert(ctx, membership); err != nil {
		return nil, fmt.Errorf("setting team membership: %w", err)
	}
	return membership, nil
}

func (s *HierarchyService) DeleteTeamMembership(ctx context.Context, principal domain.AuthenticatedPrincipal, organizationID, teamID, principalID string) error {
	if err := s.authorization.Authorize(ctx, principal, domain.PermissionTeamsManage, domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}); err != nil {
		return err
	}
	if _, err := s.teams.GetByID(ctx, principal.TenantID, organizationID, teamID); err != nil {
		return fmt.Errorf("getting team for membership removal: %w", err)
	}
	if err := s.teamMembers.Delete(ctx, principal.TenantID, organizationID, teamID, principalID); err != nil {
		return fmt.Errorf("deleting team membership: %w", err)
	}
	return nil
}

func (s *HierarchyService) requireAssignablePrincipal(ctx context.Context, actor domain.AuthenticatedPrincipal, principalID string) error {
	principal, err := s.principals.GetByID(ctx, principalID)
	if err != nil {
		return fmt.Errorf("getting membership principal: %w", err)
	}
	if principal.Status != domain.PrincipalStatusActive {
		return domain.ErrUnauthorized
	}
	if s.membership == nil {
		return domain.ErrMembershipCheckUnavailable
	}
	identity, err := s.principals.GetIdentity(ctx, principalID, actor.Provider)
	if err != nil {
		return fmt.Errorf("getting membership principal identity: %w", err)
	}
	if err := s.membership.VerifyTenantMembership(ctx, actor.Provider, actor.ExternalAccountID, identity.ExternalSubject); err != nil {
		return fmt.Errorf("verifying tenant membership: %w", err)
	}
	return nil
}

func tenantAdministrator(principal domain.AuthenticatedPrincipal) bool {
	return principal.TenantRole == domain.TenantRoleOwner || principal.TenantRole == domain.TenantRoleAdmin
}
