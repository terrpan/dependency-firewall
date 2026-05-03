package port

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// TenantBundleProvider retrieves proxy-ready tenant bundles.
type TenantBundleProvider interface {
	GetTenantBundle(ctx context.Context, tenantID string) (*domain.TenantBundle, error)
}
