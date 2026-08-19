package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// TenantResponse is the wire form of a tenant, the isolation boundary that owns policies, upstreams, decisions and
// audit records. Its ID is the value callers pass as X-Tenant-ID to scope control-plane and proxy requests.
type TenantResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toTenantResponse(t *domain.Tenant) *TenantResponse {
	return &TenantResponse{
		ID:        t.ID,
		Name:      t.Name,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

func toTenantsResponse(tenants []domain.Tenant) []*TenantResponse {
	result := make([]*TenantResponse, len(tenants))
	for i := range tenants {
		result[i] = toTenantResponse(&tenants[i])
	}
	return result
}
