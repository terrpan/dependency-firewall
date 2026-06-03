package domain

import "fmt"

// SeverityLevel represents a CVSS severity level.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityNone     SeverityLevel = "none"
)

// CVSSThresholdPolicyConfig configures the cvss_threshold policy type.
type CVSSThresholdPolicyConfig struct {
	MaxCVSS         *float64       `json:"max_cvss,omitempty" yaml:"max_cvss,omitempty"`
	MinimumSeverity *SeverityLevel `json:"minimum_severity,omitempty" yaml:"minimum_severity,omitempty"`
	DryRun          bool           `json:"dry_run,omitempty" yaml:"dry_run,omitempty"`
}

// Validate validates the config.
func (c *CVSSThresholdPolicyConfig) Validate() error {
	if c == nil || (c.MaxCVSS == nil && c.MinimumSeverity == nil) {
		return fmt.Errorf("missing required config keys: max_cvss or minimum_severity are required")
	}

	if c.MaxCVSS != nil && (*c.MaxCVSS < 0 || *c.MaxCVSS > 10) {
		return fmt.Errorf("max_cvss must be between 0 and 10")
	}

	if c.MinimumSeverity != nil {
		switch *c.MinimumSeverity {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone:
			// Valid severity levels
		default:
			return fmt.Errorf("invalid minimum_severity: %s", *c.MinimumSeverity)
		}
	}

	return nil
}

// DryRunEnabled reports whether dry-run mode is enabled.
func (c *CVSSThresholdPolicyConfig) DryRunEnabled() bool {
	return c != nil && c.DryRun
}
