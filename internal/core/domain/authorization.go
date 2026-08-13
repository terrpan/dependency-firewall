package domain

type Permission string

const (
	PermissionAccountRead          Permission = "account:read"
	PermissionAccountManage        Permission = "account:manage"
	PermissionAccountDelete        Permission = "account:delete"
	PermissionMembersRead          Permission = "members:read"
	PermissionMembersInvite        Permission = "members:invite"
	PermissionMembersManage        Permission = "members:manage"
	PermissionOrganizationsRead    Permission = "organizations:read"
	PermissionOrganizationsCreate  Permission = "organizations:create"
	PermissionOrganizationsManage  Permission = "organizations:manage"
	PermissionTeamsRead            Permission = "teams:read"
	PermissionTeamsManage          Permission = "teams:manage"
	PermissionPoliciesRead         Permission = "policies:read"
	PermissionPoliciesWrite        Permission = "policies:write"
	PermissionPoliciesDelete       Permission = "policies:delete"
	PermissionWaiversRequest       Permission = "waivers:request"
	PermissionWaiversApprove       Permission = "waivers:approve"
	PermissionUpstreamsRead        Permission = "upstreams:read"
	PermissionUpstreamsWrite       Permission = "upstreams:write"
	PermissionUpstreamsDelete      Permission = "upstreams:delete"
	PermissionCredentialsRead      Permission = "credentials:read"
	PermissionCredentialsWrite     Permission = "credentials:write"
	PermissionCredentialsRevoke    Permission = "credentials:revoke"
	PermissionEvaluationsRead      Permission = "evaluations:read"
	PermissionDependencyGraphsRead Permission = "dependency-graphs:read"
	PermissionAuditRead            Permission = "audit:read"
	PermissionCacheInvalidate      Permission = "cache:invalidate"
)

type TenantRole string

const (
	TenantRoleOwner  TenantRole = "owner"
	TenantRoleAdmin  TenantRole = "admin"
	TenantRoleMember TenantRole = "member"
)

type AuthenticatedPrincipal struct {
	Principal         Principal
	TenantID          string
	TenantRole        TenantRole
	Provider          string
	ExternalAccountID string
}

// VerifiedIdentity is the provider-neutral result of human session verification.
// It contains external identifiers only; local Tenant and Principal resolution is separate.
type VerifiedIdentity struct {
	Provider          string
	Subject           string
	ExternalAccountID string
	TenantRole        TenantRole
	SessionID         string
}

type AuthorizationScope struct {
	TenantID       string
	OrganizationID string
	TeamID         string
}

type AuthorizationDenialReason string

const (
	AuthorizationDenialUnauthenticated        AuthorizationDenialReason = "unauthenticated"
	AuthorizationDenialTenantMismatch         AuthorizationDenialReason = "tenant_mismatch"
	AuthorizationDenialOrganizationNotFound   AuthorizationDenialReason = "organization_not_found"
	AuthorizationDenialTeamNotFound           AuthorizationDenialReason = "team_not_found"
	AuthorizationDenialOrganizationUnassigned AuthorizationDenialReason = "organization_unassigned"
	AuthorizationDenialTeamMembershipRequired AuthorizationDenialReason = "team_membership_required"
	AuthorizationDenialInsufficientPermission AuthorizationDenialReason = "insufficient_permission"
)

type AuthorizationError struct {
	Reason AuthorizationDenialReason
}

func (e *AuthorizationError) Error() string { return string(e.Reason) }
