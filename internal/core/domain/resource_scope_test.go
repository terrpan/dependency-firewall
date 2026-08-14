package domain

import (
	"errors"
	"testing"
)

func TestPolicyScopeValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{name: "account", policy: Policy{ScopeKind: PolicyScopeAccount, WaiverMode: PolicyWaiverNone}},
		{name: "Organization", policy: Policy{ScopeKind: PolicyScopeOrganization, OrganizationID: "org-1", WaiverMode: PolicyWaiverApprovalRequired}},
		{name: "account with Organization", policy: Policy{ScopeKind: PolicyScopeAccount, OrganizationID: "org-1", WaiverMode: PolicyWaiverNone}, wantErr: true},
		{name: "Organization missing ancestor", policy: Policy{ScopeKind: PolicyScopeOrganization, WaiverMode: PolicyWaiverNone}, wantErr: true},
		{name: "unsupported waiver mode", policy: Policy{ScopeKind: PolicyScopeAccount, WaiverMode: "automatic"}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.ValidateScope()
			if test.wantErr && !errors.Is(err, ErrInvalidResourceScope) {
				t.Fatalf("ValidateScope() error = %v, want ErrInvalidResourceScope", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("ValidateScope() error = %v", err)
			}
		})
	}
}

func TestUpstreamScopeValidation(t *testing.T) {
	tests := []struct {
		name     string
		upstream Upstream
		wantErr  bool
	}{
		{name: "Tenant shared", upstream: Upstream{ScopeKind: UpstreamScopeTenantShared}},
		{name: "Organization shared", upstream: Upstream{ScopeKind: UpstreamScopeOrganizationShared, OrganizationID: "org-1"}},
		{name: "Team local", upstream: Upstream{ScopeKind: UpstreamScopeTeamLocal, OrganizationID: "org-1", TeamID: "team-1"}},
		{name: "Tenant shared with Organization", upstream: Upstream{ScopeKind: UpstreamScopeTenantShared, OrganizationID: "org-1"}, wantErr: true},
		{name: "Organization shared with Team", upstream: Upstream{ScopeKind: UpstreamScopeOrganizationShared, OrganizationID: "org-1", TeamID: "team-1"}, wantErr: true},
		{name: "Team missing Organization", upstream: Upstream{ScopeKind: UpstreamScopeTeamLocal, TeamID: "team-1"}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.upstream.ValidateScope()
			if test.wantErr && !errors.Is(err, ErrInvalidResourceScope) {
				t.Fatalf("ValidateScope() error = %v, want ErrInvalidResourceScope", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("ValidateScope() error = %v", err)
			}
		})
	}
}

func TestResourceScopeCompatibilityDefaults(t *testing.T) {
	policy := Policy{}
	policy.NormalizeScope()
	if policy.ScopeKind != PolicyScopeAccount || policy.WaiverMode != PolicyWaiverNone {
		t.Fatalf("Policy.NormalizeScope() = (%q, %q)", policy.ScopeKind, policy.WaiverMode)
	}
	organizationPolicy := Policy{ScopeKind: PolicyScopeOrganization, OrganizationID: "organization-1"}
	organizationPolicy.NormalizeScope()
	if organizationPolicy.WaiverMode != PolicyWaiverApprovalRequired {
		t.Fatalf("Organization Policy.NormalizeScope() waiver = %q", organizationPolicy.WaiverMode)
	}

	upstream := Upstream{}
	upstream.NormalizeScope()
	if upstream.ScopeKind != UpstreamScopeTenantShared {
		t.Fatalf("Upstream.NormalizeScope() = %q", upstream.ScopeKind)
	}
}
