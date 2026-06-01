package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func licensePolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeLicense,
			Summary:                 "Match specific licenses",
			Description:             "Matches artifacts whose declared licenses contain any configured SPDX identifier.",
			Help:                    "Use this for targeted rules such as deny GPL or warn on AGPL. If license metadata is unavailable, the policy skips.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionAllow, domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM},
			RequiredCapabilities:    []domain.UpstreamCapability{domain.UpstreamCapabilityLicenses},
			Example: `- name: block-copyleft-licenses
  type: license
  schema_version: 1
  action: deny
  priority: 30
  config:
    licenses:
      - GPL-3.0-only
      - AGPL-3.0-only`,
		},
		condition.License{},
		true,
		configTypeMatcher[*domain.LicensePolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.LicensePolicyConfig{} }),
	)
}

func licenseAllowlistPolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeLicenseAllowlist,
			Summary:                 "Allow only approved licenses",
			Description:             "Denies artifacts whose declared licenses are outside the configured approved SPDX list.",
			Help:                    "Use this for strict approved-license enforcement. This policy must use action deny and can separately deny or skip unlicensed artifacts and unavailable license metadata.",
			CurrentSchemaVersion:    2,
			SupportedSchemaVersions: []int{1, 2},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM},
			RequiredCapabilities:    []domain.UpstreamCapability{domain.UpstreamCapabilityLicenses},
			Example: `- name: allow-approved-licenses
  type: license_allowlist
  schema_version: 2
  action: deny
  priority: 30
  config:
    licenses:
      - MIT
      - Apache-2.0
      - BSD-3-Clause
    unlicensed_behavior: deny
    unavailable_metadata_behavior: skip`,
		},
		condition.LicenseAllowlist{},
		true,
		licenseAllowlistConfigMatches,
		configSchema(1, func() domain.PolicyConfig { return &domain.LicenseAllowlistPolicyConfig{} }),
		configSchema(2, func() domain.PolicyConfig { return &domain.LicenseAllowlistPolicyConfigV2{} }),
	)
}

func licenseAllowlistConfigMatches(config domain.PolicyConfig) bool {
	switch config.(type) {
	case *domain.LicenseAllowlistPolicyConfig, *domain.LicenseAllowlistPolicyConfigV2:
		return true
	default:
		return false
	}
}
