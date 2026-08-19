package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func defineDenyPolicyV1[T domain.PolicyConfig](
	descriptor domain.PolicyTypeDescriptor,
	conditionEvaluator condition.Condition,
	ecosystem domain.EcosystemType,
	requiredCapability domain.UpstreamCapability,
	requiresExternalMetadata bool,
	newConfig func() T,
) policyDefinition {
	descriptor.CurrentSchemaVersion = 1
	descriptor.SupportedSchemaVersions = []int{1}
	descriptor.SupportedActions = []domain.PolicyAction{domain.PolicyActionDeny}
	descriptor.SupportedEcosystems = []domain.EcosystemType{ecosystem}
	descriptor.RequiredCapabilities = []domain.UpstreamCapability{requiredCapability}

	return definePolicy(
		descriptor,
		conditionEvaluator,
		requiresExternalMetadata,
		configTypeMatcher[T],
		configSchema(1, func() domain.PolicyConfig { return newConfig() }),
	)
}

func minimumAgePolicyDefinition() policyDefinition {
	return defineDenyPolicyV1(
		domain.PolicyTypeDescriptor{
			Type:        domain.PolicyTypeMinimumAge,
			Summary:     "Block newly published packages",
			Description: "Matches artifacts published fewer than the configured number of days ago.",
			Help:        "Use this to reduce exposure to fresh supply-chain attacks. Supports dry_run and exclude_packages.",
			Example: `- name: block-brand-new-packages
  type: minimum_age
  schema_version: 1
  action: deny
  priority: 20
  config:
    min_age_days: 7`,
		},
		condition.MinimumAge{},
		domain.EcosystemNPM,
		domain.UpstreamCapabilityPublishTime,
		true,
		func() *domain.MinimumAgePolicyConfig { return &domain.MinimumAgePolicyConfig{} },
	)
}

func maximumAgePolicyDefinition() policyDefinition {
	return defineDenyPolicyV1(
		domain.PolicyTypeDescriptor{
			Type:        domain.PolicyTypeMaximumAge,
			Summary:     "Block outdated packages",
			Description: "Matches artifacts published more than the configured number of days ago.",
			Help:        "Use this to phase out stale dependencies. Supports dry_run and exclude_packages.",
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
		domain.EcosystemNPM,
		domain.UpstreamCapabilityPublishTime,
		true,
		func() *domain.MaximumAgePolicyConfig { return &domain.MaximumAgePolicyConfig{} },
	)
}
