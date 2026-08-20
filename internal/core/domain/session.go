package domain

// SessionOrganization models a session organization.
type SessionOrganization struct {
	Organization Organization
	Role         OrganizationRole
	Permissions  []Permission
}

// Session models a session.
type Session struct {
	Tenant             Tenant
	Principal          Principal
	TenantRole         TenantRole
	Organizations      []SessionOrganization
	AccountPermissions []Permission
	CompatibilityMode  bool
}
