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
}

type sessionTenantGetter interface {
	GetByID(ctx context.Context, id string) (*domain.Tenant, error)
}

type sessionOrganizationLister interface {
	ListByTenant(ctx context.Context, tenantID string) ([]domain.Organization, error)
}

func NewSessionService(tenants sessionTenantGetter, organizations sessionOrganizationLister) *SessionService {
	return &SessionService{tenants: tenants, organizations: organizations}
}

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

func IsSessionTenantNotFound(err error) bool {
	return errors.Is(err, domain.ErrTenantNotFound)
}
