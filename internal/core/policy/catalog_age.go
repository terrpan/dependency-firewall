package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func minimumAgePolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeMinimumAge,
			Summary:                 "Block newly published packages",
			Description:             "Matches artifacts published fewer than the configured number of days ago.",
			Help:                    "Use this to reduce exposure to fresh supply-chain attacks. Supports dry_run and exclude_packages.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM},
			RequiredCapabilities:    []domain.UpstreamCapability{domain.UpstreamCapabilityPublishTime},
			Example: `- name: block-brand-new-packages
  type: minimum_age
  schema_version: 1
  action: deny
  priority: 20
  config:
    min_age_days: 7`,
		},
		condition.MinimumAge{},
		true,
		configTypeMatcher[*domain.MinimumAgePolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.MinimumAgePolicyConfig{} }),
	)
}

func maximumAgePolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeMaximumAge,
			Summary:                 "Block outdated packages",
			Description:             "Matches artifacts published more than the configured number of days ago.",
			Help:                    "Use this to phase out stale dependencies. Supports dry_run and exclude_packages.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM},
			RequiredCapabilities:    []domain.UpstreamCapability{domain.UpstreamCapabilityPublishTime},
			Example: `- name: block-outdated-packages
  type: maximum_age
  schema_version: 1
  action: deny
  priority: 25
  config:
    max_age_days: 730
    dry_run: true`,
		},
		condition.MaximumAge{},
		true,
		configTypeMatcher[*domain.MaximumAgePolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.MaximumAgePolicyConfig{} }),
	)
}
