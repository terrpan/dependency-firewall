package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// ValidatePolicy validates a single domain policy.
func ValidatePolicy(p domain.Policy) error {
	p.NormalizeScope()
	if err := p.ValidateScope(); err != nil {
		return invalidPolicyf("%v", err)
	}
	if strings.TrimSpace(p.TenantID) == "" {
		return invalidPolicyf("tenant_id is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return invalidPolicyf("name is required")
	}
	definition, ok := policyDefinitionFor(p.Type)
	if !ok {
		return invalidPolicyf("unknown policy type %q", p.Type)
	}
	if _, ok := validActions[string(p.Action)]; !ok {
		return invalidPolicyf(
			"invalid action %q, must be %q or %q",
			p.Action,
			domain.PolicyActionAllow,
			domain.PolicyActionDeny,
		)
	}
	if !slices.Contains(definition.descriptor.SupportedActions, p.Action) {
		if len(definition.descriptor.SupportedActions) == 1 {
			return invalidPolicyf(
				"policy type %q requires action %q",
				p.Type,
				definition.descriptor.SupportedActions[0],
			)
		}
		return invalidPolicyf("policy type %q does not support action %q", p.Type, p.Action)
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
	if err := p.Config.Validate(); err != nil {
		return invalidPolicyf("%v", err)
	}
	if err := p.Target.Validate(); err != nil {
		return invalidPolicyf("%v", err)
	}
	return nil
}

// ValidatePolicies validates a policy set.
func ValidatePolicies(policies []domain.Policy) error {
	seenNames := make(map[string]int, len(policies))
	for i, p := range policies {
		p.NormalizeScope()
		if err := ValidatePolicy(p); err != nil {
			return fmt.Errorf("%w: policy %d (%q): %v", domain.ErrInvalidPolicy, i, p.Name, err)
		}
		scopeName := strings.Join([]string{string(p.ScopeKind), p.OrganizationID, p.Name}, "\x00")
		if firstIndex, exists := seenNames[scopeName]; exists {
			return fmt.Errorf(
				"%w: policy %d (%q): duplicate policy name %q already used by policy %d",
				domain.ErrInvalidPolicy,
				i,
				p.Name,
				p.Name,
				firstIndex,
			)
		}
		seenNames[scopeName] = i
	}
	return nil
}
