package domain

import "time"

// PolicyAction is what a policy rule does when matched.
type PolicyAction string

// A deny action blocks the artifact when the policy condition matches. An allow action only records a positive match
// for audit; it grants no exemption from any deny policy, because evaluation is deny-wins.
const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
)

// PolicyType identifies the kind of policy condition.
type PolicyType string

// The policy types compiled into the catalog. Each value selects a pure evaluator plus a typed, schema-versioned
// config struct, and declares the ecosystems and upstream enrichment capabilities it requires. New behavior is added by
// introducing a type here rather than by making policy configuration more expressive.
const (
	PolicyTypeCVSSThreshold      PolicyType = "cvss_threshold"
	PolicyTypeMinimumAge         PolicyType = "minimum_age"
	PolicyTypeMaximumAge         PolicyType = "maximum_age"
	PolicyTypeBlockMutableTag    PolicyType = "block_mutable_tag"
	PolicyTypeScorecard          PolicyType = "scorecard"
	PolicyTypeLicense            PolicyType = "license"
	PolicyTypeLicenseAllowlist   PolicyType = "license_allowlist"
	PolicyTypeAllowlist          PolicyType = "allowlist"
	PolicyTypeNamespaceAllowlist PolicyType = "namespace_allowlist"
	PolicyTypeBlocklist          PolicyType = "blocklist"
)

// Policy represents a tenant's policy rule.
type Policy struct {
	ID             string
	TenantID       string
	OrganizationID string
	ScopeKind      PolicyScope
	WaiverMode     PolicyWaiverMode
	UpstreamID     string
	Name           string
	Type           PolicyType
	Action         PolicyAction
	SchemaVersion  int
	Config         PolicyConfig
	Target         *PolicyTarget
	Priority       int
	Enabled        bool
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// MaxRetainedPolicyVersions is how many point-in-time snapshots are kept per policy. Older versions are pruned on
// write, so rollback can only target one of the most recent snapshots.
const MaxRetainedPolicyVersions = 3

// PolicyVersion stores a point-in-time snapshot of a tenant policy.
type PolicyVersion struct {
	TenantID       string
	PolicyID       string
	Version        int
	OrganizationID string
	ScopeKind      PolicyScope
	WaiverMode     PolicyWaiverMode
	UpstreamID     string
	Name           string
	Type           PolicyType
	Action         PolicyAction
	SchemaVersion  int
	Config         PolicyConfig
	Target         *PolicyTarget
	Priority       int
	Enabled        bool
	CreatedAt      time.Time
}

// PolicySetRevision records the canonical tenant policy-set hash at a point in time.
type PolicySetRevision struct {
	ID         string
	TenantID   string
	Generation int64
	PolicyHash string
	CreatedAt  time.Time
}

// DependencyUnknownAction controls how a target-aware policy behaves when graph context is unknown.
type DependencyUnknownAction string

// When a target-aware policy cannot be resolved against dependency graph evidence, warn (the default) records a
// warning without changing the outcome, deny evaluates the policy as if the target matched, and skip ignores it.
const (
	DependencyUnknownWarn DependencyUnknownAction = "warn"
	DependencyUnknownDeny DependencyUnknownAction = "deny"
	DependencyUnknownSkip DependencyUnknownAction = "skip"
)

// PolicyTarget restricts a policy to dependency graph context.
type PolicyTarget struct {
	DependencyScopes []DependencyScope       `json:"dependency_scope,omitempty"`
	DependencyTypes  []DependencyType        `json:"dependency_types,omitempty"`
	OnUnknown        DependencyUnknownAction `json:"on_unknown,omitempty"`
}
