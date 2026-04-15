package policy

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"gopkg.in/yaml.v3"
)

var knownPolicyTypes = map[string]domain.PolicyType{
	string(domain.PolicyTypeCVSSThreshold):   domain.PolicyTypeCVSSThreshold,
	string(domain.PolicyTypeMinimumAge):      domain.PolicyTypeMinimumAge,
	string(domain.PolicyTypeMaximumAge):      domain.PolicyTypeMaximumAge,
	string(domain.PolicyTypeBlockMutableTag): domain.PolicyTypeBlockMutableTag,
	string(domain.PolicyTypeAllowlist):       domain.PolicyTypeAllowlist,
	string(domain.PolicyTypeBlocklist):       domain.PolicyTypeBlocklist,
}

var validActions = map[string]domain.PolicyAction{
	string(domain.PolicyActionAllow): domain.PolicyActionAllow,
	string(domain.PolicyActionDeny):  domain.PolicyActionDeny,
}

// ParseFile parses raw YAML bytes into a PolicyFile.
func ParseFile(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	return &pf, nil
}

// ToDomainPolicies converts a parsed PolicyFile into domain Policy objects.
func ToDomainPolicies(file *PolicyFile) ([]domain.Policy, error) {
	if file.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	policies := make([]domain.Policy, 0, len(file.Policies))
	for i, def := range file.Policies {
		p, err := toDomainPolicy(file.TenantID, def, i)
		if err != nil {
			return nil, fmt.Errorf("policy %d (%q): %w", i, def.Name, err)
		}
		policies = append(policies, p)
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
	if def.Action == "" {
		return domain.Policy{}, fmt.Errorf("action is required")
	}

	policyType, ok := knownPolicyTypes[def.Type]
	if !ok {
		return domain.Policy{}, fmt.Errorf("unknown policy type %q", def.Type)
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

	return domain.Policy{
		TenantID: tenantID,
		Name:     def.Name,
		Type:     policyType,
		Action:   action,
		Config:   def.Config,
		Priority: priority,
		Enabled:  enabled,
		Version:  1,
	}, nil
}
