package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func allowlistPolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeAllowlist,
			Summary:                 "Match trusted namespaces",
			Description:             "Matches artifacts whose namespace is in the configured trusted list.",
			Help:                    "Use this to record positive matches for internal namespaces. Allow matches do not override later deny rules.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionAllow},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM, domain.EcosystemOCI},
			Example: `- name: allow-internal-packages
  type: allowlist
  schema_version: 1
  action: allow
  priority: 5
  config:
    namespaces:
      - mycompany
      - internal`,
		},
		condition.Allowlist{},
		false,
		configTypeMatcher[*domain.NamespaceListPolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.NamespaceListPolicyConfig{} }),
	)
}

func namespaceAllowlistPolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeNamespaceAllowlist,
			Summary:                 "Allow only approved namespaces",
			Description:             "Denies artifacts whose namespace is outside the configured approved namespace list.",
			Help:                    "Use this for fail-closed namespace enforcement such as allowing only official OCI namespaces like library or approved internal orgs.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM, domain.EcosystemOCI},
			Example: `- name: allow-only-approved-namespaces
  type: namespace_allowlist
  schema_version: 1
  action: deny
  priority: 10
  config:
    namespaces:
      - library
      - docker`,
		},
		condition.NamespaceAllowlist{},
		false,
		configTypeMatcher[*domain.NamespaceListPolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.NamespaceListPolicyConfig{} }),
	)
}

func blocklistPolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeBlocklist,
			Summary:                 "Block specific namespaces",
			Description:             "Matches artifacts whose namespace is in the configured blocked list.",
			Help:                    "Use this to block known bad scopes, registries, or organizations explicitly.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM, domain.EcosystemOCI},
			Example: `- name: block-untrusted-scopes
  type: blocklist
  schema_version: 1
  action: deny
  priority: 30
  config:
    namespaces:
      - evil-corp
      - abandoned-org`,
		},
		condition.Blocklist{},
		false,
		configTypeMatcher[*domain.NamespaceListPolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.NamespaceListPolicyConfig{} }),
	)
}
