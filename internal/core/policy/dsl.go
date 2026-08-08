// Package policy implements the policy DSL, parser, and evaluation engine.
package policy

// PolicyFile represents a YAML or JSON policy definition file.
type PolicyFile struct {
	TenantID string      `yaml:"tenant_id" json:"tenant_id"`
	Policies []PolicyDef `yaml:"policies" json:"policies"`
}

// PolicyDef is a single policy definition from a YAML or JSON document.
type PolicyDef struct {
	UpstreamID    *string        `yaml:"upstream_id" json:"upstream_id"`
	Name          string         `yaml:"name" json:"name"`
	Type          string         `yaml:"type" json:"type"`
	SchemaVersion *int           `yaml:"schema_version" json:"schema_version"`
	Action        string         `yaml:"action" json:"action"`
	Target        *TargetDef     `yaml:"target" json:"target"`
	Priority      *int           `yaml:"priority" json:"priority"`
	Config        map[string]any `yaml:"config" json:"config"`
	Enabled       *bool          `yaml:"enabled" json:"enabled"`
}

// TargetDef is an optional policy target block from a YAML or JSON document.
type TargetDef struct {
	DependencyScopes []string `yaml:"dependency_scope" json:"dependency_scope"`
	DependencyTypes  []string `yaml:"dependency_types" json:"dependency_types"`
	OnUnknown        string   `yaml:"on_unknown" json:"on_unknown"`
}
