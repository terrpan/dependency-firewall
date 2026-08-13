package api

import "github.com/danielterry/dependency-firewall/internal/core/domain"

type OperationAuthorizationPolicy struct {
	AuthenticationRequired bool
	Permission             domain.Permission
	Bootstrap              bool
	FreshMembership        bool
	ScopedAuthorization    bool
}

var controlPlaneOperationPolicies = map[string]OperationAuthorizationPolicy{
	"get-health":              {},
	"get-session":             {AuthenticationRequired: true, Permission: domain.PermissionAccountRead},
	"bootstrap-session":       {AuthenticationRequired: true, Permission: domain.PermissionAccountRead, Bootstrap: true},
	"create-tenant":           {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsCreate},
	"list-tenants":            {AuthenticationRequired: true, Permission: domain.PermissionAccountRead},
	"get-tenant":              {AuthenticationRequired: true, Permission: domain.PermissionAccountRead},
	"update-tenant":           {AuthenticationRequired: true, Permission: domain.PermissionAccountManage, FreshMembership: true},
	"delete-tenant":           {AuthenticationRequired: true, Permission: domain.PermissionAccountDelete, FreshMembership: true},
	"create-policy":           {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite, FreshMembership: true},
	"list-policies":           {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"get-policy":              {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"update-policy":           {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite, FreshMembership: true},
	"delete-policy":           {AuthenticationRequired: true, Permission: domain.PermissionPoliciesDelete, FreshMembership: true},
	"list-policy-versions":    {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"rollback-policy":         {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite, FreshMembership: true},
	"list-policy-types":       {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"import-policies":         {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite, FreshMembership: true},
	"create-upstream":         {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsWrite, FreshMembership: true},
	"list-upstreams":          {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsRead},
	"get-upstream":            {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsRead},
	"update-upstream":         {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsWrite, FreshMembership: true},
	"delete-upstream":         {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsDelete, FreshMembership: true},
	"list-evaluations":        {AuthenticationRequired: true, Permission: domain.PermissionEvaluationsRead},
	"list-audit-events":       {AuthenticationRequired: true, Permission: domain.PermissionAuditRead},
	"clear-decision-cache":    {AuthenticationRequired: true, Permission: domain.PermissionCacheInvalidate},
	"clear-metadata-cache":    {AuthenticationRequired: true, Permission: domain.PermissionCacheInvalidate},
	"list-dependency-graphs":  {AuthenticationRequired: true, Permission: domain.PermissionDependencyGraphsRead},
	"get-dependency-graph":    {AuthenticationRequired: true, Permission: domain.PermissionDependencyGraphsRead},
	"list-organizations":      {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsRead, ScopedAuthorization: true},
	"create-organization":     {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsCreate},
	"get-organization":        {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsRead, ScopedAuthorization: true},
	"update-organization":     {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsManage, ScopedAuthorization: true},
	"get-organization-member": {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsRead, ScopedAuthorization: true},
	"set-organization-member": {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsManage, FreshMembership: true, ScopedAuthorization: true},
	"list-teams":              {AuthenticationRequired: true, Permission: domain.PermissionTeamsRead, ScopedAuthorization: true},
	"create-team":             {AuthenticationRequired: true, Permission: domain.PermissionTeamsManage, ScopedAuthorization: true},
	"get-team":                {AuthenticationRequired: true, Permission: domain.PermissionTeamsRead, ScopedAuthorization: true},
	"update-team":             {AuthenticationRequired: true, Permission: domain.PermissionTeamsManage, ScopedAuthorization: true},
	"get-team-member":         {AuthenticationRequired: true, Permission: domain.PermissionTeamsRead, ScopedAuthorization: true},
	"set-team-member":         {AuthenticationRequired: true, Permission: domain.PermissionTeamsManage, FreshMembership: true, ScopedAuthorization: true},
	"delete-team-member":      {AuthenticationRequired: true, Permission: domain.PermissionTeamsManage, FreshMembership: true, ScopedAuthorization: true},
}

func ControlPlaneOperationPolicy(operationID string) (OperationAuthorizationPolicy, bool) {
	policy, ok := controlPlaneOperationPolicies[operationID]
	return policy, ok
}
