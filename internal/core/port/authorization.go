package port

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// TenantAuthorizer authorizes one principal capability within one Tenant.
type TenantAuthorizer interface {
	Authorize(
		ctx context.Context,
		principal domain.AuthenticatedPrincipal,
		tenantID string,
		permission domain.Permission,
	) error
}

// TenantAccessLister lists Tenant IDs where a principal has one capability.
type TenantAccessLister interface {
	ListTenantIDs(
		ctx context.Context,
		principal domain.AuthenticatedPrincipal,
		permission domain.Permission,
	) ([]string, error)
}

// TenantAccess combines point authorization and accessible-Tenant listing.
type TenantAccess interface {
	TenantAuthorizer
	TenantAccessLister
}

// SystemAuthorizer authorizes a deployment-scoped capability.
type SystemAuthorizer interface {
	AuthorizeSystem(
		ctx context.Context,
		principal domain.AuthenticatedPrincipal,
		permission domain.Permission,
	) error
}
