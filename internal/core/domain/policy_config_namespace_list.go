package domain

import "fmt"

// NamespaceListPolicyConfig configures the allowlist and blocklist policy types.
type NamespaceListPolicyConfig struct {
	Namespaces []string `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	DryRun     bool     `json:"dry_run,omitempty"    yaml:"dry_run,omitempty"`
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
