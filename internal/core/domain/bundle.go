package domain

import "time"

// TenantBundle is the tenant-scoped runtime contract required by the proxy.
type TenantBundle struct {
	Tenant      Tenant
	TenantID    string
	Revision    string
	GeneratedAt time.Time
	Policies    []Policy
	Upstreams   []Upstream
	Credentials []DataPlaneCredentialVerifier
}
