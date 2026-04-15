// Package policy implements the policy DSL, parser, and evaluation engine.
package policy

// PolicyFile represents a YAML policy definition file.
type PolicyFile struct {
	TenantID string      `yaml:"tenant_id"`
	Policies []PolicyDef `yaml:"policies"`
}

// PolicyDef is a single policy definition from YAML.
type PolicyDef struct {
	Name     string         `yaml:"name"`
	Type     string         `yaml:"type"`
	Action   string         `yaml:"action"`
	Priority *int           `yaml:"priority"`
	Config   map[string]any `yaml:"config"`
	Enabled  *bool          `yaml:"enabled"`
}
