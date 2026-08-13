package domain

type SessionOrganization struct {
	Organization Organization
	Role         OrganizationRole
	Permissions  []Permission
}

type Session struct {
	Tenant             Tenant
	Principal          Principal
	TenantRole         TenantRole
	Organizations      []SessionOrganization
	AccountPermissions []Permission
	CompatibilityMode  bool
}
