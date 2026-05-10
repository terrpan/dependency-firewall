// Package domain defines the core domain model for the dependency firewall.
package domain

import (
	"fmt"
	"strings"
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
	PolicyTypeScorecard          PolicyType = "scorecard"
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

// ScorecardUnavailableBehavior controls how the scorecard policy handles
// missing repository identity or unavailable Scorecard data.
type ScorecardUnavailableBehavior string

const (
	ScorecardUnavailableBehaviorDeny ScorecardUnavailableBehavior = "deny"
	ScorecardUnavailableBehaviorSkip ScorecardUnavailableBehavior = "skip"
)

// ScorecardPolicyConfig configures the scorecard policy type.
type ScorecardPolicyConfig struct {
	MinScore                     *float64                     `json:"min_score,omitempty" yaml:"min_score,omitempty"`
	Checks                       map[string]float64           `json:"checks,omitempty" yaml:"checks,omitempty"`
	UnavailableScorecardBehavior ScorecardUnavailableBehavior `json:"unavailable_scorecard_behavior,omitempty" yaml:"unavailable_scorecard_behavior,omitempty"`
	DryRun                       bool                         `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *ScorecardPolicyConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("scorecard config is required")
	}
	if c.MinScore == nil && len(c.Checks) == 0 {
		return fmt.Errorf("at least one of %q or %q is required", "min_score", "checks")
	}
	if c.MinScore != nil {
		if err := validateScorecardScore(*c.MinScore, "min_score"); err != nil {
			return err
		}
	}
	if err := validateScorecardUnavailableBehavior(c.UnavailableScorecardBehavior, "unavailable_scorecard_behavior"); err != nil {
		return err
	}

	if len(c.Checks) == 0 {
		return nil
	}

	normalizedChecks := make(map[string]float64, len(c.Checks))
	for rawName, minScore := range c.Checks {
		normalizedName := NormalizeScorecardCheckName(rawName)
		if normalizedName == "" {
			return fmt.Errorf("scorecard check names must not be empty")
		}
		if err := validateScorecardScore(minScore, fmt.Sprintf("checks.%s", normalizedName)); err != nil {
			return err
		}
		if _, exists := normalizedChecks[normalizedName]; exists {
			return fmt.Errorf("duplicate scorecard check threshold %q", normalizedName)
		}
		normalizedChecks[normalizedName] = minScore
	}
	c.Checks = normalizedChecks

	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *ScorecardPolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// EffectiveUnavailableScorecardBehavior returns the configured behavior,
// defaulting to deny when omitted.
func (c *ScorecardPolicyConfig) EffectiveUnavailableScorecardBehavior() ScorecardUnavailableBehavior {
	if c == nil || c.UnavailableScorecardBehavior == "" {
		return ScorecardUnavailableBehaviorDeny
	}
	return c.UnavailableScorecardBehavior
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

// LicenseAllowlistMissingBehavior controls how license_allowlist handles
// artifacts without usable license data.
type LicenseAllowlistMissingBehavior string

const (
	LicenseAllowlistMissingBehaviorDeny LicenseAllowlistMissingBehavior = "deny"
	LicenseAllowlistMissingBehaviorSkip LicenseAllowlistMissingBehavior = "skip"
)

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

// LicenseAllowlistPolicyConfigV2 configures license_allowlist schema v2 with
// explicit handling for missing license data.
type LicenseAllowlistPolicyConfigV2 struct {
	Licenses                    []string                        `json:"licenses,omitempty" yaml:"licenses,omitempty"`
	UnlicensedBehavior          LicenseAllowlistMissingBehavior `json:"unlicensed_behavior,omitempty" yaml:"unlicensed_behavior,omitempty"`
	UnavailableMetadataBehavior LicenseAllowlistMissingBehavior `json:"unavailable_metadata_behavior,omitempty" yaml:"unavailable_metadata_behavior,omitempty"`
	DryRun                      bool                            `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *LicenseAllowlistPolicyConfigV2) Validate() error {
	if c == nil || len(c.Licenses) == 0 {
		return fmt.Errorf("missing required config key %q", "licenses")
	}
	if err := validateLicenseAllowlistMissingBehavior(c.UnlicensedBehavior, "unlicensed_behavior"); err != nil {
		return err
	}
	if err := validateLicenseAllowlistMissingBehavior(c.UnavailableMetadataBehavior, "unavailable_metadata_behavior"); err != nil {
		return err
	}
	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *LicenseAllowlistPolicyConfigV2) DryRunEnabled() bool {
	return c != nil && c.DryRun
}

// EffectiveUnlicensedBehavior returns the configured behavior, defaulting to
// deny when omitted.
func (c *LicenseAllowlistPolicyConfigV2) EffectiveUnlicensedBehavior() LicenseAllowlistMissingBehavior {
	if c == nil || c.UnlicensedBehavior == "" {
		return LicenseAllowlistMissingBehaviorDeny
	}
	return c.UnlicensedBehavior
}

// EffectiveUnavailableMetadataBehavior returns the configured behavior,
// defaulting to deny when omitted.
func (c *LicenseAllowlistPolicyConfigV2) EffectiveUnavailableMetadataBehavior() LicenseAllowlistMissingBehavior {
	if c == nil || c.UnavailableMetadataBehavior == "" {
		return LicenseAllowlistMissingBehaviorDeny
	}
	return c.UnavailableMetadataBehavior
}

func validateLicenseAllowlistMissingBehavior(value LicenseAllowlistMissingBehavior, fieldName string) error {
	if value == "" {
		return nil
	}

	switch value {
	case LicenseAllowlistMissingBehaviorDeny, LicenseAllowlistMissingBehaviorSkip:
		return nil
	default:
		return fmt.Errorf("invalid config value for %q: %q", fieldName, value)
	}
}

func validateScorecardUnavailableBehavior(value ScorecardUnavailableBehavior, fieldName string) error {
	if value == "" {
		return nil
	}

	switch value {
	case ScorecardUnavailableBehaviorDeny, ScorecardUnavailableBehaviorSkip:
		return nil
	default:
		return fmt.Errorf("invalid config value for %q: %q", fieldName, value)
	}
}

func validateScorecardScore(value float64, fieldName string) error {
	if value < 0 || value > 10 {
		return fmt.Errorf("invalid config value for %q: must be between 0 and 10", fieldName)
	}
	return nil
}

// NormalizeScorecardCheckName canonicalizes Scorecard check names so policy
// config and enrichment results can match regardless of case or separator style.
func NormalizeScorecardCheckName(value string) string {
	replaced := strings.NewReplacer("_", " ", "-", " ").Replace(strings.TrimSpace(strings.ToLower(value)))
	parts := strings.Fields(replaced)
	return strings.Join(parts, "-")
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
	ID           string
	TenantID     string
	Name         string
	Ecosystem    EcosystemType
	BaseURL      string
	Capabilities []UpstreamCapability
	Auth         *UpstreamAuth
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UpstreamAuthType identifies the server-side authentication mode for an upstream registry.
type UpstreamAuthType string

const (
	UpstreamAuthNone        UpstreamAuthType = "none"
	UpstreamAuthBasic       UpstreamAuthType = "basic"
	UpstreamAuthBearerToken UpstreamAuthType = "bearer_token"
)

// UpstreamAuth holds server-side upstream registry authentication.
//
// Secret is intentionally not exposed by delivery response DTOs. For basic auth it
// contains the password or PAT; for bearer token auth it contains the token.
type UpstreamAuth struct {
	Type      UpstreamAuthType
	Username  string
	Secret    string
	UpdatedAt time.Time
}

// Configured reports whether the auth config should authenticate upstream requests.
func (a *UpstreamAuth) Configured() bool {
	return a != nil && a.Type != "" && a.Type != UpstreamAuthNone
}

// UpstreamAuthConfigured reports whether the upstream has usable auth configured.
func (u Upstream) UpstreamAuthConfigured() bool {
	return u.Auth.Configured()
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
	RequestID string
	Artifact  ArtifactIdentity
	Upstream  Upstream
	Metadata  *ArtifactMetadata
	Timestamp time.Time
}

// ArtifactMetadata holds enrichment data about an artifact.
type ArtifactMetadata struct {
	PublishedAt      *time.Time
	MaxCVSS          *float64
	Licenses         []string
	Vulnerabilities  []Vulnerability
	IsMutableTag     bool
	SourceRepository *SourceRepository
	Scorecard        *ScorecardResult
}

// SourceRepository identifies the source repository associated with an artifact.
type SourceRepository struct {
	Host  string
	Owner string
	Repo  string
}

// ProjectURI returns the Scorecard-compatible repository identifier.
func (r SourceRepository) ProjectURI() string {
	host := strings.TrimSpace(strings.ToLower(r.Host))
	owner := strings.TrimSpace(r.Owner)
	repo := strings.TrimSpace(r.Repo)
	if host == "" || owner == "" || repo == "" {
		return ""
	}
	return host + "/" + owner + "/" + repo
}

// DisplayName returns a human-friendly repository identifier.
func (r SourceRepository) DisplayName() string {
	owner := strings.TrimSpace(r.Owner)
	repo := strings.TrimSpace(r.Repo)
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}

// ScorecardResult holds hosted Scorecard data for a source repository.
type ScorecardResult struct {
	Score             *float64
	Checks            map[string]float64
	UnavailableReason string
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
	UpstreamID    string
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
	UpstreamID    string
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
