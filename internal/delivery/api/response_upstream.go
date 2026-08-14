package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

// UpstreamResponse is the wire form of a configured upstream registry. Capabilities is the effective profile after
// legacy defaults are upgraded, and SupportedPolicyTypes is derived from it so clients can tell which policy types may
// be scoped to this upstream without reimplementing the compatibility rules.
type UpstreamResponse struct {
	ID                   string               `json:"id"`
	TenantID             string               `json:"tenant_id"`
	OrganizationID       string               `json:"organization_id,omitempty"`
	TeamID               string               `json:"team_id,omitempty"`
	Scope                domain.UpstreamScope `json:"scope"`
	Name                 string               `json:"name"`
	Ecosystem            string               `json:"ecosystem"`
	BaseURL              string               `json:"base_url"`
	Capabilities         []string             `json:"capabilities"`
	SupportedPolicyTypes []string             `json:"supported_policy_types"`
	Auth                 UpstreamAuthResponse `json:"auth"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at"`
}

// UpstreamAuthResponse describes an upstream's outbound authentication without ever exposing the stored credential:
// only the mode, whether a usable secret is present, the basic-auth username, and when it was last changed.
type UpstreamAuthResponse struct {
	Type       string     `json:"type"`
	Configured bool       `json:"configured"`
	Username   string     `json:"username,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

func toUpstreamResponse(u *domain.Upstream) *UpstreamResponse {
	u.NormalizeScope()
	supportedPolicyTypes := corepolicy.SupportedPolicyTypesForUpstream(*u)
	policyTypes := make([]string, len(supportedPolicyTypes))
	for i := range supportedPolicyTypes {
		policyTypes[i] = string(supportedPolicyTypes[i])
	}
	effectiveCapabilities := u.EffectiveCapabilities()

	auth := UpstreamAuthResponse{
		Type:       string(domain.UpstreamAuthNone),
		Configured: false,
	}
	if u.Auth != nil {
		auth.Type = string(u.Auth.Type)
		auth.Configured = u.Auth.Configured()
		auth.Username = u.Auth.Username
		if !u.Auth.UpdatedAt.IsZero() {
			updatedAt := u.Auth.UpdatedAt
			auth.UpdatedAt = &updatedAt
		}
	}

	return &UpstreamResponse{
		ID:                   u.ID,
		TenantID:             u.TenantID,
		OrganizationID:       u.OrganizationID,
		TeamID:               u.TeamID,
		Scope:                u.ScopeKind,
		Name:                 u.Name,
		Ecosystem:            string(u.Ecosystem),
		BaseURL:              u.BaseURL,
		Capabilities:         domain.UpstreamCapabilityStrings(effectiveCapabilities),
		SupportedPolicyTypes: policyTypes,
		Auth:                 auth,
		CreatedAt:            u.CreatedAt,
		UpdatedAt:            u.UpdatedAt,
	}
}

func toUpstreamsResponse(upstreams []domain.Upstream) []*UpstreamResponse {
	result := make([]*UpstreamResponse, len(upstreams))
	for i := range upstreams {
		result[i] = toUpstreamResponse(&upstreams[i])
	}
	return result
}
