package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

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
