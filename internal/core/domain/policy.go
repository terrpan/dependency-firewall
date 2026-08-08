package domain

import "time"

// PolicyAction is what a policy rule does when matched.
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
)

// PolicyType identifies the kind of policy condition.
type PolicyType string

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
	ID            string
	TenantID      string
	UpstreamID    string
	Name          string
	Type          PolicyType
	Action        PolicyAction
	SchemaVersion int
	Config        PolicyConfig
	Target        *PolicyTarget
	Priority      int
	Enabled       bool
	Version       int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const MaxRetainedPolicyVersions = 3

// PolicyVersion stores a point-in-time snapshot of a tenant policy.
type PolicyVersion struct {
	PolicyID      string
	Version       int
	UpstreamID    string
	Name          string
	Type          PolicyType
	Action        PolicyAction
	SchemaVersion int
	Config        PolicyConfig
	Target        *PolicyTarget
	Priority      int
	Enabled       bool
	CreatedAt     time.Time
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
