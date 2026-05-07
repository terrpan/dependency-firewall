package policy

import (
	"fmt"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// ValidatePolicy validates a single domain policy.
func ValidatePolicy(p domain.Policy) error {
	if strings.TrimSpace(p.TenantID) == "" {
		return invalidPolicyf("tenant_id is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return invalidPolicyf("name is required")
	}
	if _, ok := knownPolicyTypes[string(p.Type)]; !ok {
		return invalidPolicyf("unknown policy type %q", p.Type)
	}
	if _, ok := validActions[string(p.Action)]; !ok {
		return invalidPolicyf("invalid action %q, must be %q or %q", p.Action, domain.PolicyActionAllow, domain.PolicyActionDeny)
	}
	schemaVersion, err := normalizeSchemaVersion(p.Type, p.SchemaVersion)
	if err != nil {
		return err
	}
	if err := validateSchemaVersion(p.Type, schemaVersion); err != nil {
		return err
	}
	if p.Config == nil {
		return invalidPolicyf("config is required")
	}
	if !configTypeMatchesPolicy(p.Type, p.Config) {
		return invalidPolicyf("config type %T does not match policy type %q", p.Config, p.Type)
	}
	if p.Type == domain.PolicyTypeLicenseAllowlist && p.Action != domain.PolicyActionDeny {
		return invalidPolicyf("policy type %q requires action %q", p.Type, domain.PolicyActionDeny)
	}
	if p.Type == domain.PolicyTypeScorecard && p.Action != domain.PolicyActionDeny {
		return invalidPolicyf("policy type %q requires action %q", p.Type, domain.PolicyActionDeny)
	}
	if p.Type == domain.PolicyTypeNamespaceAllowlist && p.Action != domain.PolicyActionDeny {
		return invalidPolicyf("policy type %q requires action %q", p.Type, domain.PolicyActionDeny)
	}
	if err := p.Config.Validate(); err != nil {
		return invalidPolicyf("%v", err)
	}
	return nil
}

// ValidatePolicies validates a policy set.
func ValidatePolicies(policies []domain.Policy) error {
	seenNames := make(map[string]int, len(policies))
	for i, p := range policies {
		if err := ValidatePolicy(p); err != nil {
			return fmt.Errorf("%w: policy %d (%q): %v", domain.ErrInvalidPolicy, i, p.Name, err)
		}
		if firstIndex, exists := seenNames[p.Name]; exists {
			return fmt.Errorf("%w: policy %d (%q): duplicate policy name %q already used by policy %d", domain.ErrInvalidPolicy, i, p.Name, p.Name, firstIndex)
		}
		seenNames[p.Name] = i
	}
	return nil
}
