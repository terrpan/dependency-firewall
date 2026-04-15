// Package domain defines the core domain model for the dependency firewall.
package domain

import (
	"time"
)

// EcosystemType identifies the package ecosystem.
type EcosystemType string

const (
	EcosystemNPM EcosystemType = "npm"
	EcosystemOCI EcosystemType = "oci"
)

// DecisionOutcome is the result of policy evaluation.
type DecisionOutcome string

const (
	DecisionAllow DecisionOutcome = "allow"
	DecisionDeny  DecisionOutcome = "deny"
)

// PolicyAction is what a policy rule does when matched.
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
)

// PolicyType identifies the kind of policy condition.
type PolicyType string

const (
	PolicyTypeCVSSThreshold   PolicyType = "cvss_threshold"
	PolicyTypeMinimumAge      PolicyType = "minimum_age"
	PolicyTypeMaximumAge      PolicyType = "maximum_age"
	PolicyTypeBlockMutableTag PolicyType = "block_mutable_tag"
	PolicyTypeAllowlist       PolicyType = "allowlist"
	PolicyTypeBlocklist       PolicyType = "blocklist"
)

// ReasonCategory classifies why a decision was made.
type ReasonCategory string

const (
	ReasonPolicyMatch          ReasonCategory = "policy_match"
	ReasonNoMatchingPolicy     ReasonCategory = "no_matching_policy"
	ReasonEnrichmentFailure    ReasonCategory = "enrichment_failure"
	ReasonCached               ReasonCategory = "cached"
	ReasonCategoryEvaluationError ReasonCategory = "evaluation_error"
)

// Tenant represents an isolated customer account.
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Upstream represents a configured upstream registry.
type Upstream struct {
	ID        string
	TenantID  string
	Name      string
	Ecosystem EcosystemType
	BaseURL   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ArtifactIdentity is the canonical, normalized identifier for a package or image.
type ArtifactIdentity struct {
	Ecosystem EcosystemType
	Namespace string // e.g., npm scope or OCI registry/org
	Name      string
	Version   string // semver for npm, tag or digest for OCI
	Digest    string // immutable content hash (sha256:...), populated when resolved
}

// AccessRequest is the normalized input to the policy engine.
type AccessRequest struct {
	TenantID  string
	Artifact  ArtifactIdentity
	Upstream  Upstream
	Metadata  *ArtifactMetadata
	Timestamp time.Time
}

// ArtifactMetadata holds enrichment data about an artifact.
type ArtifactMetadata struct {
	PublishedAt     *time.Time
	MaxCVSS         *float64
	Vulnerabilities []Vulnerability
	IsMutableTag    bool
}

// Vulnerability holds data from enrichment sources like OSV.
type Vulnerability struct {
	ID       string
	Severity string
	CVSS     float64
	Summary  string
}

// Policy represents a tenant's policy rule.
type Policy struct {
	ID        string
	TenantID  string
	Name      string
	Type      PolicyType
	Action    PolicyAction
	Config    map[string]any
	Priority  int
	Enabled   bool
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Decision records the outcome of a policy evaluation.
type Decision struct {
	ID          string
	TenantID    string
	Artifact    ArtifactIdentity
	Outcome     DecisionOutcome
	PolicyID    string
	Reason      string // user-facing reason
	Reasons     []EvaluationReason
	CachedAt    *time.Time
	EvaluatedAt time.Time
}

// EvaluationReason is one reason contributing to a decision.
type EvaluationReason struct {
	PolicyID   string
	PolicyName string
	Category   ReasonCategory
	Action     PolicyAction
	Message    string
}
