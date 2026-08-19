package domain

import "fmt"

// BlockMutableTagPolicyConfig configures the block_mutable_tag policy type.
type BlockMutableTagPolicyConfig struct {
	Tags   []string `json:"tags,omitempty"    yaml:"tags,omitempty"`
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
