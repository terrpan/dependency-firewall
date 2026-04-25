// Package domain defines the core domain model for the dependency firewall.
package domain

import (
	"fmt"
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
	PolicyTypeCVSSThreshold      PolicyType = "cvss_threshold"
	PolicyTypeMinimumAge         PolicyType = "minimum_age"
	PolicyTypeMaximumAge         PolicyType = "maximum_age"
	PolicyTypeBlockMutableTag    PolicyType = "block_mutable_tag"
	PolicyTypeLicense            PolicyType = "license"
	PolicyTypeLicenseAllowlist   PolicyType = "license_allowlist"
	PolicyTypeAllowlist          PolicyType = "allowlist"
	PolicyTypeNamespaceAllowlist PolicyType = "namespace_allowlist"
	PolicyTypeBlocklist          PolicyType = "blocklist"
)

// PolicyConfig is the typed configuration for a policy.
type PolicyConfig interface {
	Validate() error
	DryRunEnabled() bool
}

// CVSSThresholdPolicyConfig configures the cvss_threshold policy type.
type CVSSThresholdPolicyConfig struct {
	MaxCVSS *float64 `json:"max_cvss,omitempty" yaml:"max_cvss,omitempty"`
	DryRun  bool     `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *CVSSThresholdPolicyConfig) Validate() error {
	if c == nil || c.MaxCVSS == nil {
		return fmt.Errorf("missing required config key %q", "max_cvss")
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *CVSSThresholdPolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// MinimumAgePolicyConfig configures the minimum_age policy type.
type MinimumAgePolicyConfig struct {
	MinAgeDays      *int     `json:"min_age_days,omitempty" yaml:"min_age_days,omitempty"`
	ExcludePackages []string `json:"exclude_packages,omitempty" yaml:"exclude_packages,omitempty"`
	DryRun          bool     `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *MinimumAgePolicyConfig) Validate() error {
	if c == nil || c.MinAgeDays == nil {
		return fmt.Errorf("missing required config key %q", "min_age_days")
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *MinimumAgePolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// MaximumAgePolicyConfig configures the maximum_age policy type.
type MaximumAgePolicyConfig struct {
	MaxAgeDays      *int     `json:"max_age_days,omitempty" yaml:"max_age_days,omitempty"`
	ExcludePackages []string `json:"exclude_packages,omitempty" yaml:"exclude_packages,omitempty"`
	DryRun          bool     `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *MaximumAgePolicyConfig) Validate() error {
	if c == nil || c.MaxAgeDays == nil {
		return fmt.Errorf("missing required config key %q", "max_age_days")
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *MaximumAgePolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// BlockMutableTagPolicyConfig configures the block_mutable_tag policy type.
type BlockMutableTagPolicyConfig struct {
	Tags   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	DryRun bool     `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *BlockMutableTagPolicyConfig) Validate() error {
	if c == nil || len(c.Tags) == 0 {
		return fmt.Errorf("missing required config key %q", "tags")
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *BlockMutableTagPolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// LicensePolicyConfig configures the license policy type.
type LicensePolicyConfig struct {
	Licenses []string `json:"licenses,omitempty" yaml:"licenses,omitempty"`
	DryRun   bool     `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *LicensePolicyConfig) Validate() error {
	if c == nil || len(c.Licenses) == 0 {
		return fmt.Errorf("missing required config key %q", "licenses")
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *LicensePolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// LicenseAllowlistPolicyConfig configures the license_allowlist policy type.
type LicenseAllowlistPolicyConfig struct {
	Licenses []string `json:"licenses,omitempty" yaml:"licenses,omitempty"`
	DryRun   bool     `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *LicenseAllowlistPolicyConfig) Validate() error {
	if c == nil || len(c.Licenses) == 0 {
		return fmt.Errorf("missing required config key %q", "licenses")
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *LicenseAllowlistPolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// NamespaceListPolicyConfig configures the allowlist and blocklist policy types.
type NamespaceListPolicyConfig struct {
	Namespaces []string `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	DryRun     bool     `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *NamespaceListPolicyConfig) Validate() error {
	if c == nil || len(c.Namespaces) == 0 {
		return fmt.Errorf("missing required config key %q", "namespaces")
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *NamespaceListPolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// ReasonCategory classifies why a decision was made.
type ReasonCategory string

const (
	ReasonPolicyMatch             ReasonCategory = "policy_match"
	ReasonPolicyWarning           ReasonCategory = "policy_warning"
	ReasonNoMatchingPolicy        ReasonCategory = "no_matching_policy"
	ReasonEnrichmentFailure       ReasonCategory = "enrichment_failure"
	ReasonCached                  ReasonCategory = "cached"
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
	Licenses        []string
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
	ID            string
	TenantID      string
	Name          string
	Type          PolicyType
	Action        PolicyAction
	SchemaVersion int
	Config        PolicyConfig
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
	Name          string
	Type          PolicyType
	Action        PolicyAction
	SchemaVersion int
	Config        PolicyConfig
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

// Decision records the outcome of a policy evaluation.
type Decision struct {
	ID          string
	TenantID    string
	Artifact    ArtifactIdentity
	Outcome     DecisionOutcome
	PolicyID    string
	PolicyHash  string
	Reason      string // user-facing reason
	Reasons     []EvaluationReason
	Warnings    []string // user-facing warnings from warn-mode policies
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
