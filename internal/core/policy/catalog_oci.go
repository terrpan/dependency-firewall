package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func blockMutableTagPolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeBlockMutableTag,
			Summary:                 "Block mutable OCI tags",
			Description:             "Matches OCI artifacts requested by mutable tags such as latest or dev.",
			Help:                    "Use this to require immutable image references. Best for OCI manifests and tag-based pulls.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemOCI},
			RequiredCapabilities:    []domain.UpstreamCapability{domain.UpstreamCapabilityManifestDigestLookup},
			Example: `- name: block-latest-tag
  type: block_mutable_tag
  schema_version: 1
  action: deny
  priority: 15
  config:
    tags:
      - latest`,
		},
		condition.BlockMutableTag{},
		false,
		configTypeMatcher[*domain.BlockMutableTagPolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.BlockMutableTagPolicyConfig{} }),
	)
}
