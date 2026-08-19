package domain

import "time"

// UpstreamAuthType identifies the server-side authentication mode for an upstream registry.
type UpstreamAuthType string

// How the firewall authenticates its own outbound requests to an upstream registry: not at all, with HTTP basic
// credentials (username plus password or PAT), or with a bearer token. Clients of the proxy never see these values.
const (
	UpstreamAuthNone        UpstreamAuthType = "none"
	UpstreamAuthBasic       UpstreamAuthType = "basic"
	UpstreamAuthBearerToken UpstreamAuthType = "bearer_token"
)

// UpstreamAuth holds server-side upstream registry authentication.
//
// Secret is intentionally not exposed by delivery response DTOs. For basic auth it
// contains the password or PAT; for bearer token auth it contains the token.
type UpstreamAuth struct {
	Type      UpstreamAuthType
	Username  string
	Secret    string
	UpdatedAt time.Time
}

// Configured reports whether the auth config should authenticate upstream requests.
func (a *UpstreamAuth) Configured() bool {
	return a != nil && a.Type != "" && a.Type != UpstreamAuthNone
}
