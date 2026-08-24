package domain

// Permission identifies one Dependency Firewall application capability.
type Permission string

// Application permissions used by current and planned Tenant workflows.
const (
	PermissionTenantRead    Permission = "tenant:read"
	PermissionTenantManage  Permission = "tenant:manage"
	PermissionTenantCreate  Permission = "tenant:create"
	PermissionTenantDelete  Permission = "tenant:delete"
	PermissionProxyRead     Permission = "proxy:read"
	PermissionProxyManage   Permission = "proxy:manage"
	PermissionMembersRead   Permission = "members:read"
	PermissionMembersManage Permission = "members:manage"
)
