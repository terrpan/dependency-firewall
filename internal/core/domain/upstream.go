package domain

import "time"

// Upstream represents a configured upstream registry.
type Upstream struct {
	ID             string
	TenantID       string
	OrganizationID string
	TeamID         string
	ScopeKind      UpstreamScope
	Name           string
	Ecosystem      EcosystemType
	BaseURL        string
	Capabilities   []UpstreamCapability
	Auth           *UpstreamAuth
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UpstreamAuthConfigured reports whether the upstream has usable auth configured.
func (u Upstream) UpstreamAuthConfigured() bool {
	return u.Auth.Configured()
}
