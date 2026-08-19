package domain

import "fmt"

// MinimumAgePolicyConfig configures the minimum_age policy type.
type MinimumAgePolicyConfig struct {
	MinAgeDays      *int     `json:"min_age_days,omitempty"     yaml:"min_age_days,omitempty"`
	ExcludePackages []string `json:"exclude_packages,omitempty" yaml:"exclude_packages,omitempty"`
	DryRun          bool     `json:"dry_run,omitempty"          yaml:"dry_run,omitempty"`
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
	MaxAgeDays      *int     `json:"max_age_days,omitempty"     yaml:"max_age_days,omitempty"`
	ExcludePackages []string `json:"exclude_packages,omitempty" yaml:"exclude_packages,omitempty"`
	DryRun          bool     `json:"dry_run,omitempty"          yaml:"dry_run,omitempty"`
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
