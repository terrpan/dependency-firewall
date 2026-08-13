package api

import "github.com/danielterry/dependency-firewall/internal/core/domain"

type OperationAuthorizationPolicy struct {
	AuthenticationRequired bool
	Permission             domain.Permission
}

var controlPlaneOperationPolicies = map[string]OperationAuthorizationPolicy{
	"get-health":             {},
	"get-session":            {AuthenticationRequired: true, Permission: domain.PermissionAccountRead},
	"create-tenant":          {AuthenticationRequired: true, Permission: domain.PermissionOrganizationsCreate},
	"list-tenants":           {AuthenticationRequired: true, Permission: domain.PermissionAccountRead},
	"get-tenant":             {AuthenticationRequired: true, Permission: domain.PermissionAccountRead},
	"update-tenant":          {AuthenticationRequired: true, Permission: domain.PermissionAccountManage},
	"delete-tenant":          {AuthenticationRequired: true, Permission: domain.PermissionAccountDelete},
	"create-policy":          {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite},
	"list-policies":          {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"get-policy":             {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"update-policy":          {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite},
	"delete-policy":          {AuthenticationRequired: true, Permission: domain.PermissionPoliciesDelete},
	"list-policy-versions":   {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"rollback-policy":        {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite},
	"list-policy-types":      {AuthenticationRequired: true, Permission: domain.PermissionPoliciesRead},
	"import-policies":        {AuthenticationRequired: true, Permission: domain.PermissionPoliciesWrite},
	"create-upstream":        {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsWrite},
	"list-upstreams":         {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsRead},
	"get-upstream":           {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsRead},
	"update-upstream":        {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsWrite},
	"delete-upstream":        {AuthenticationRequired: true, Permission: domain.PermissionUpstreamsDelete},
	"list-evaluations":       {AuthenticationRequired: true, Permission: domain.PermissionEvaluationsRead},
	"list-audit-events":      {AuthenticationRequired: true, Permission: domain.PermissionAuditRead},
	"clear-decision-cache":   {AuthenticationRequired: true, Permission: domain.PermissionCacheInvalidate},
	"clear-metadata-cache":   {AuthenticationRequired: true, Permission: domain.PermissionCacheInvalidate},
	"list-dependency-graphs": {AuthenticationRequired: true, Permission: domain.PermissionDependencyGraphsRead},
	"get-dependency-graph":   {AuthenticationRequired: true, Permission: domain.PermissionDependencyGraphsRead},
}

func ControlPlaneOperationPolicy(operationID string) (OperationAuthorizationPolicy, bool) {
	policy, ok := controlPlaneOperationPolicies[operationID]
	return policy, ok
}
