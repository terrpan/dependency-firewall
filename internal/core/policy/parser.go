package policy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

var validActions = map[string]domain.PolicyAction{
	string(domain.PolicyActionAllow): domain.PolicyActionAllow,
	string(domain.PolicyActionDeny):  domain.PolicyActionDeny,
}

// ParseFile parses raw YAML or JSON bytes into a File.
func ParseFile(data []byte) (*File, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("parsing policy file: %w: empty policy document", domain.ErrInvalidPolicy)
	}

	var pf File
	if looksLikeJSON(trimmed) {
		if err := json.Unmarshal(trimmed, &pf); err != nil {
			return nil, fmt.Errorf("parsing policy JSON: %w", err)
		}
		return &pf, nil
	}
	if err := yaml.Unmarshal(trimmed, &pf); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	return &pf, nil
}

// ToDomainPolicies converts a parsed File into domain Policy objects.
func ToDomainPolicies(file *File) ([]domain.Policy, error) {
	return ToDomainPoliciesForTenant(file, "")
}

// ToDomainPoliciesForTenant converts a parsed File into domain Policy
// objects for the provided tenant. When tenantID is non-empty, it overrides any
// tenant_id defined in the YAML file.
func ToDomainPoliciesForTenant(file *File, tenantID string) ([]domain.Policy, error) {
	effectiveTenantID := tenantID
	if effectiveTenantID == "" {
		effectiveTenantID = file.TenantID
	}
	if effectiveTenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	policies := make([]domain.Policy, 0, len(file.Policies))
	for i, def := range file.Policies {
		p, err := toDomainPolicy(effectiveTenantID, def, i)
		if err != nil {
			return nil, fmt.Errorf("policy %d (%q): %w", i, def.Name, err)
		}
		if err := ValidatePolicy(p); err != nil {
			return nil, fmt.Errorf("policy %d (%q): %w", i, def.Name, err)
		}
		policies = append(policies, p)
	}
	if err := ValidatePolicies(policies); err != nil {
		return nil, err
	}
	return policies, nil
}

func toDomainPolicy(tenantID string, def Def, index int) (domain.Policy, error) {
	if def.Name == "" {
		return domain.Policy{}, fmt.Errorf("name is required")
	}
	if def.Type == "" {
		return domain.Policy{}, fmt.Errorf("type is required")
	}
	if def.SchemaVersion == nil {
		return domain.Policy{}, fmt.Errorf("%w: schema_version is required", domain.ErrUnsupportedPolicySchemaVersion)
	}
	if def.Action == "" {
		return domain.Policy{}, fmt.Errorf("action is required")
	}

	policyType, ok := parsePolicyType(def.Type)
	if !ok {
		return domain.Policy{}, fmt.Errorf("unknown policy type %q", def.Type)
	}

	schemaVersion := *def.SchemaVersion
	if err := validateSchemaVersion(policyType, schemaVersion); err != nil {
		return domain.Policy{}, err
	}

	action, ok := validActions[def.Action]
	if !ok {
		return domain.Policy{}, fmt.Errorf("invalid action %q, must be \"allow\" or \"deny\"", def.Action)
	}

	enabled := true
	if def.Enabled != nil {
		enabled = *def.Enabled
	}

	priority := index
	if def.Priority != nil {
		priority = *def.Priority
	}

	config, err := DecodeConfigValue(policyType, schemaVersion, def.Config)
	if err != nil {
		return domain.Policy{}, err
	}
	target, err := toDomainTarget(def.Target)
	if err != nil {
		return domain.Policy{}, err
	}

	return domain.Policy{
		TenantID:      tenantID,
		UpstreamID:    stringValue(def.UpstreamID),
		Name:          def.Name,
		Type:          policyType,
		Action:        action,
		SchemaVersion: schemaVersion,
		Config:        config,
		Target:        target,
		Priority:      priority,
		Enabled:       enabled,
		Version:       1,
	}, nil
}

func looksLikeJSON(data []byte) bool {
	return len(data) > 0 && (data[0] == '{' || data[0] == '[')
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func toDomainTarget(def *TargetDef) (*domain.PolicyTarget, error) {
	if def == nil {
		return nil, nil
	}
	target := &domain.PolicyTarget{
		DependencyScopes: make([]domain.DependencyScope, 0, len(def.DependencyScopes)),
		DependencyTypes:  make([]domain.DependencyType, 0, len(def.DependencyTypes)),
		OnUnknown:        domain.DependencyUnknownAction(def.OnUnknown),
	}
	for _, value := range def.DependencyScopes {
		target.DependencyScopes = append(target.DependencyScopes, domain.DependencyScope(value))
	}
	for _, value := range def.DependencyTypes {
		target.DependencyTypes = append(target.DependencyTypes, domain.DependencyType(value))
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	target.Normalize()
	return target, nil
}
