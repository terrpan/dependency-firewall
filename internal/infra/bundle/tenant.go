package bundle

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// TenantLookup adapts tenant bundles to the proxy tenant lookup runtime contract.
type TenantLookup struct {
	provider port.TenantBundleProvider
}

// NewTenantLookup creates a new bundle-backed tenant lookup.
func NewTenantLookup(provider port.TenantBundleProvider) *TenantLookup {
	return &TenantLookup{provider: provider}
}

// GetByID returns tenant runtime data from the tenant bundle.
func (l *TenantLookup) GetByID(ctx context.Context, id string) (*domain.Tenant, error) {
	bundle, err := l.provider.GetTenantBundle(ctx, id)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, domain.ErrTenantNotFound
	}

	tenant := bundle.Tenant
	if tenant.ID == "" {
		tenant.ID = bundle.TenantID
	}
	if tenant.ID == "" || tenant.ID != id {
		return nil, domain.ErrTenantNotFound
	}

	return &tenant, nil
}
