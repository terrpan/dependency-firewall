package domain

import "fmt"

// PolicyScope identifies where a policy is owned and applied.
type PolicyScope string

const (
	PolicyScopeAccount      PolicyScope = "account"
	PolicyScopeOrganization PolicyScope = "organization"
)

// PolicyWaiverMode controls whether exact-artifact waivers may be approved.
type PolicyWaiverMode string

const (
	PolicyWaiverNone             PolicyWaiverMode = "none"
	PolicyWaiverApprovalRequired PolicyWaiverMode = "approval_required"
)

// UpstreamScope identifies an upstream registry's visibility boundary.
type UpstreamScope string

const (
	UpstreamScopeTenantShared       UpstreamScope = "tenant_shared"
	UpstreamScopeOrganizationShared UpstreamScope = "organization_shared"
	UpstreamScopeTeamLocal          UpstreamScope = "team_local"
)

// NormalizeScope fills compatibility defaults for an account policy.
func (p *Policy) NormalizeScope() {
	if p.ScopeKind == "" {
		p.ScopeKind = PolicyScopeAccount
	}
	if p.WaiverMode == "" {
		p.WaiverMode = PolicyWaiverNone
		if p.ScopeKind == PolicyScopeOrganization {
			p.WaiverMode = PolicyWaiverApprovalRequired
		}
	}
}

// ValidateScope rejects policy ancestry that does not match its scope kind.
func (p Policy) ValidateScope() error {
	switch p.ScopeKind {
	case PolicyScopeAccount:
		if p.OrganizationID != "" {
			return fmt.Errorf("%w: account policy cannot select an Organization", ErrInvalidResourceScope)
		}
	case PolicyScopeOrganization:
		if p.OrganizationID == "" {
			return fmt.Errorf("%w: Organization policy requires organization_id", ErrInvalidResourceScope)
		}
	default:
		return fmt.Errorf("%w: unsupported policy scope %q", ErrInvalidResourceScope, p.ScopeKind)
	}

	switch p.WaiverMode {
	case PolicyWaiverNone, PolicyWaiverApprovalRequired:
		return nil
	default:
		return fmt.Errorf("%w: unsupported policy waiver mode %q", ErrInvalidResourceScope, p.WaiverMode)
	}
}

// NormalizeScope fills the compatibility default for a Tenant-shared upstream.
func (u *Upstream) NormalizeScope() {
	if u.ScopeKind == "" {
		u.ScopeKind = UpstreamScopeTenantShared
	}
}

// ValidateScope rejects upstream ancestry that does not match its visibility kind.
func (u Upstream) ValidateScope() error {
	switch u.ScopeKind {
	case UpstreamScopeTenantShared:
		if u.OrganizationID != "" || u.TeamID != "" {
			return fmt.Errorf("%w: Tenant-shared upstream cannot select an Organization or Team", ErrInvalidResourceScope)
		}
	case UpstreamScopeOrganizationShared:
		if u.OrganizationID == "" || u.TeamID != "" {
			return fmt.Errorf("%w: Organization-shared upstream requires only organization_id", ErrInvalidResourceScope)
		}
	case UpstreamScopeTeamLocal:
		if u.OrganizationID == "" || u.TeamID == "" {
			return fmt.Errorf("%w: Team-local upstream requires organization_id and team_id", ErrInvalidResourceScope)
		}
	default:
		return fmt.Errorf("%w: unsupported upstream scope %q", ErrInvalidResourceScope, u.ScopeKind)
	}
	return nil
}
