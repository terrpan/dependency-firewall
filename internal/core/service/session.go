package service

import (
	"context"
	"errors"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// SessionService builds the provider-neutral session contract. The disabled
// path is deliberately explicit and exists only for the one-release compatibility mode.
type SessionService struct {
	tenants       sessionTenantGetter
	organizations sessionOrganizationLister
	organization  sessionOrganizationGetter
	memberships   sessionMembershipLister
}

type sessionTenantGetter interface {
	GetByID(ctx context.Context, id string) (*domain.Tenant, error)
}

type sessionOrganizationLister interface {
	ListByTenant(ctx context.Context, tenantID string) ([]domain.Organization, error)
}

type sessionOrganizationGetter interface {
	GetByID(ctx context.Context, tenantID, id string) (*domain.Organization, error)
}

type sessionMembershipLister interface {
	ListByPrincipal(ctx context.Context, tenantID, principalID string) ([]domain.OrganizationMembership, error)
}

// NewSessionService constructs a new SessionService.
func NewSessionService(
	tenants sessionTenantGetter,
	organizations sessionOrganizationLister,
	memberships ...sessionMembershipLister,
) *SessionService {
	service := &SessionService{tenants: tenants, organizations: organizations}
	service.organization, _ = organizations.(sessionOrganizationGetter)
	if len(memberships) > 0 {
		service.memberships = memberships[0]
	}
	return service
}

// CompatibilitySession performs the compatibility session operation.
func (s *SessionService) CompatibilitySession(ctx context.Context, tenantID string) (*domain.Session, error) {
	if tenantID == "" {
		return nil, domain.ErrTenantNotFound
	}
	tenant, err := s.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	organizations, err := s.organizations.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	sessionOrganizations := make([]domain.SessionOrganization, 0, len(organizations))
	for _, organization := range organizations {
		if organization.Status != domain.OrganizationStatusActive {
			continue
		}
		sessionOrganizations = append(sessionOrganizations, domain.SessionOrganization{
			Organization: organization,
			Role:         domain.OrganizationRoleAdmin,
			Permissions:  PermissionsForOrganizationRole(domain.OrganizationRoleAdmin),
		})
	}

	return &domain.Session{
		Tenant: *tenant,
		Principal: domain.Principal{
			ID:          "compatibility-disabled",
			DisplayName: "Compatibility administrator",
			Status:      domain.PrincipalStatusActive,
		},
		TenantRole:         domain.TenantRoleOwner,
		Organizations:      sessionOrganizations,
		AccountPermissions: PermissionsForTenantRole(domain.TenantRoleOwner),
		CompatibilityMode:  true,
	}, nil
}

// AuthenticatedSession assembles a session for an authenticated principal.
func (s *SessionService) AuthenticatedSession( //nolint:gocognit // session assembly branches across identity providers
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
) (*domain.Session, error) {
	tenant, err := s.tenants.GetByID(ctx, principal.TenantID)
	if err != nil {
		return nil, err
	}
	organizations := make([]domain.SessionOrganization, 0)
	if principal.TenantRole == domain.TenantRoleOwner || principal.TenantRole == domain.TenantRoleAdmin {
		items, err := s.organizations.ListByTenant(ctx, principal.TenantID)
		if err != nil {
			return nil, err
		}
		for _, organization := range items {
			if organization.Status == domain.OrganizationStatusActive {
				organizations = append(organizations, domain.SessionOrganization{
					Organization: organization, Role: domain.OrganizationRoleAdmin,
					Permissions: PermissionsForOrganizationRole(domain.OrganizationRoleAdmin),
				})
			}
		}
	} else if s.memberships != nil && s.organization != nil {
		items, err := s.memberships.ListByPrincipal(ctx, principal.TenantID, principal.Principal.ID)
		if err != nil {
			return nil, err
		}
		for _, membership := range items {
			organization, err := s.organization.GetByID(ctx, principal.TenantID, membership.OrganizationID)
			if errors.Is(err, domain.ErrOrganizationNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if organization.Status == domain.OrganizationStatusActive {
				organizations = append(organizations, domain.SessionOrganization{
					Organization: *organization, Role: membership.Role,
					Permissions: PermissionsForOrganizationRole(membership.Role),
				})
			}
		}
	}
	return &domain.Session{
		Tenant: *tenant, Principal: principal.Principal, TenantRole: principal.TenantRole,
		Organizations: organizations, AccountPermissions: PermissionsForTenantRole(principal.TenantRole),
	}, nil
}

// IsSessionTenantNotFound reports whether session tenant not found holds.
func IsSessionTenantNotFound(err error) bool {
	return errors.Is(err, domain.ErrTenantNotFound)
}
