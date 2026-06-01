package domain

import (
	"fmt"
	"strings"
)

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
