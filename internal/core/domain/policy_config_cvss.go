package domain

import "fmt"

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
