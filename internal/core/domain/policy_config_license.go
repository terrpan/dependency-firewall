package domain

import "fmt"

// LicensePolicyConfig configures the license policy type.
type LicensePolicyConfig struct {
	Licenses []string `json:"licenses,omitempty" yaml:"licenses,omitempty"`
	DryRun   bool     `json:"dry_run,omitempty"  yaml:"dry_run,omitempty"`
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

// Deny fails closed, treating an unlicensed artifact or unavailable license metadata as a violation; skip lets the
// request past this policy so other policies decide. Schema 1 always denies both cases; schema 2 configures each.
const (
	LicenseAllowlistMissingBehaviorDeny LicenseAllowlistMissingBehavior = "deny"
	LicenseAllowlistMissingBehaviorSkip LicenseAllowlistMissingBehavior = "skip"
)

// LicenseAllowlistPolicyConfig configures the license_allowlist policy type.
type LicenseAllowlistPolicyConfig struct {
	Licenses []string `json:"licenses,omitempty" yaml:"licenses,omitempty"`
	DryRun   bool     `json:"dry_run,omitempty"  yaml:"dry_run,omitempty"`
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
	Licenses                    []string                        `json:"licenses,omitempty"                      yaml:"licenses,omitempty"`
	UnlicensedBehavior          LicenseAllowlistMissingBehavior `json:"unlicensed_behavior,omitempty"           yaml:"unlicensed_behavior,omitempty"`
	UnavailableMetadataBehavior LicenseAllowlistMissingBehavior `json:"unavailable_metadata_behavior,omitempty" yaml:"unavailable_metadata_behavior,omitempty"`
	DryRun                      bool                            `json:"dry_run,omitempty"                       yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *LicenseAllowlistPolicyConfigV2) Validate() error {
	if c == nil || len(c.Licenses) == 0 {
		return fmt.Errorf("missing required config key %q", "licenses")
	}
	if err := validateLicenseAllowlistMissingBehavior(c.UnlicensedBehavior, "unlicensed_behavior"); err != nil {
		return err
	}
	if err := validateLicenseAllowlistMissingBehavior(
		c.UnavailableMetadataBehavior,
		"unavailable_metadata_behavior",
	); err != nil {
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
