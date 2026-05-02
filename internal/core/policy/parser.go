package policy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"gopkg.in/yaml.v3"
)

var knownPolicyTypes = map[string]domain.PolicyType{
	string(domain.PolicyTypeCVSSThreshold):      domain.PolicyTypeCVSSThreshold,
	string(domain.PolicyTypeMinimumAge):         domain.PolicyTypeMinimumAge,
	string(domain.PolicyTypeMaximumAge):         domain.PolicyTypeMaximumAge,
	string(domain.PolicyTypeBlockMutableTag):    domain.PolicyTypeBlockMutableTag,
	string(domain.PolicyTypeLicense):            domain.PolicyTypeLicense,
	string(domain.PolicyTypeLicenseAllowlist):   domain.PolicyTypeLicenseAllowlist,
	string(domain.PolicyTypeAllowlist):          domain.PolicyTypeAllowlist,
	string(domain.PolicyTypeNamespaceAllowlist): domain.PolicyTypeNamespaceAllowlist,
	string(domain.PolicyTypeBlocklist):          domain.PolicyTypeBlocklist,
}

var validActions = map[string]domain.PolicyAction{
	string(domain.PolicyActionAllow): domain.PolicyActionAllow,
	string(domain.PolicyActionDeny):  domain.PolicyActionDeny,
}

// ParseFile parses raw YAML or JSON bytes into a PolicyFile.
func ParseFile(data []byte) (*PolicyFile, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("parsing policy file: %w: empty policy document", domain.ErrInvalidPolicy)
	}

	var pf PolicyFile
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

// ToDomainPolicies converts a parsed PolicyFile into domain Policy objects.
func ToDomainPolicies(file *PolicyFile) ([]domain.Policy, error) {
	return ToDomainPoliciesForTenant(file, "")
}

// ToDomainPoliciesForTenant converts a parsed PolicyFile into domain Policy
// objects for the provided tenant. When tenantID is non-empty, it overrides any
// tenant_id defined in the YAML file.
func ToDomainPoliciesForTenant(file *PolicyFile, tenantID string) ([]domain.Policy, error) {
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

func toDomainPolicy(tenantID string, def PolicyDef, index int) (domain.Policy, error) {
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

	policyType, ok := knownPolicyTypes[def.Type]
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

	return domain.Policy{
		TenantID:      tenantID,
		UpstreamID:    stringValue(def.UpstreamID),
		Name:          def.Name,
		Type:          policyType,
		Action:        action,
		SchemaVersion: schemaVersion,
		Config:        config,
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
