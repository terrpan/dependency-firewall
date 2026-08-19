package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func blockMutableTagPolicyDefinition() policyDefinition {
	return defineDenyPolicyV1(
		domain.PolicyTypeDescriptor{
			Type:        domain.PolicyTypeBlockMutableTag,
			Summary:     "Block mutable OCI tags",
			Description: "Matches OCI artifacts requested by mutable tags such as latest or dev.",
			Help:        "Use this to require immutable image references. Best for OCI manifests and tag-based pulls.",
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
		domain.EcosystemOCI,
		domain.UpstreamCapabilityManifestDigestLookup,
		false,
		func() *domain.BlockMutableTagPolicyConfig { return &domain.BlockMutableTagPolicyConfig{} },
	)
}
