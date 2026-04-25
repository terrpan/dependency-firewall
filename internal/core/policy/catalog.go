package policy

import "github.com/danielterry/dependency-firewall/internal/core/domain"

var policyTypeCatalog = []domain.PolicyTypeDescriptor{
	{
		Type:                    domain.PolicyTypeCVSSThreshold,
		Summary:                 "Block by vulnerability severity",
		Description:             "Matches artifacts whose maximum CVSS score exceeds the configured threshold.",
		Help:                    "Use this to deny or warn on vulnerable artifacts after OSV enrichment. If CVSS metadata is unavailable, the policy skips.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
		Example: `- name: block-critical-vulnerabilities
  type: cvss_threshold
  schema_version: 1
  action: deny
  priority: 10
  config:
    max_cvss: 7.0`,
	},
	{
		Type:                    domain.PolicyTypeMinimumAge,
		Summary:                 "Block newly published packages",
		Description:             "Matches artifacts published fewer than the configured number of days ago.",
		Help:                    "Use this to reduce exposure to fresh supply-chain attacks. Supports dry_run and exclude_packages.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
		Example: `- name: block-brand-new-packages
  type: minimum_age
  schema_version: 1
  action: deny
  priority: 20
  config:
    min_age_days: 7`,
	},
	{
		Type:                    domain.PolicyTypeMaximumAge,
		Summary:                 "Block outdated packages",
		Description:             "Matches artifacts published more than the configured number of days ago.",
		Help:                    "Use this to phase out stale dependencies. Supports dry_run and exclude_packages.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
		Example: `- name: block-outdated-packages
  type: maximum_age
  schema_version: 1
  action: deny
  priority: 25
  config:
    max_age_days: 730
    dry_run: true`,
	},
	{
		Type:                    domain.PolicyTypeBlockMutableTag,
		Summary:                 "Block mutable OCI tags",
		Description:             "Matches OCI artifacts requested by mutable tags such as latest or dev.",
		Help:                    "Use this to require immutable image references. Best for OCI manifests and tag-based pulls.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
		Example: `- name: block-latest-tag
  type: block_mutable_tag
  schema_version: 1
  action: deny
  priority: 15
  config:
    tags:
      - latest`,
	},
	{
		Type:                    domain.PolicyTypeLicense,
		Summary:                 "Match specific licenses",
		Description:             "Matches artifacts whose declared licenses contain any configured SPDX identifier.",
		Help:                    "Use this for targeted rules such as deny GPL or warn on AGPL. If license metadata is unavailable, the policy skips.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionAllow, domain.PolicyActionDeny},
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
	{
		Type:                    domain.PolicyTypeLicenseAllowlist,
		Summary:                 "Allow only approved licenses",
		Description:             "Denies artifacts whose declared licenses are outside the configured approved SPDX list.",
		Help:                    "Use this for strict approved-license enforcement. This policy must use action deny and fails closed when license metadata is unavailable.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
		Example: `- name: allow-approved-licenses
  type: license_allowlist
  schema_version: 1
  action: deny
  priority: 30
  config:
    licenses:
      - MIT
      - Apache-2.0
      - BSD-3-Clause`,
	},
	{
		Type:                    domain.PolicyTypeAllowlist,
		Summary:                 "Match trusted namespaces",
		Description:             "Matches artifacts whose namespace is in the configured trusted list.",
		Help:                    "Use this to record positive matches for internal namespaces. Allow matches do not override later deny rules.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionAllow},
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
	{
		Type:                    domain.PolicyTypeNamespaceAllowlist,
		Summary:                 "Allow only approved namespaces",
		Description:             "Denies artifacts whose namespace is outside the configured approved namespace list.",
		Help:                    "Use this for fail-closed namespace enforcement such as allowing only official OCI namespaces like library or approved internal orgs.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
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
	{
		Type:                    domain.PolicyTypeBlocklist,
		Summary:                 "Block specific namespaces",
		Description:             "Matches artifacts whose namespace is in the configured blocked list.",
		Help:                    "Use this to block known bad scopes, registries, or organizations explicitly.",
		CurrentSchemaVersion:    1,
		SupportedSchemaVersions: []int{1},
		SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
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
}

// TypeCatalog returns the supported policy types and their help metadata.
func TypeCatalog() []domain.PolicyTypeDescriptor {
	result := make([]domain.PolicyTypeDescriptor, len(policyTypeCatalog))
	for i := range policyTypeCatalog {
		result[i] = policyTypeCatalog[i]
		result[i].SupportedActions = append([]domain.PolicyAction(nil), policyTypeCatalog[i].SupportedActions...)
		result[i].SupportedSchemaVersions = append([]int(nil), policyTypeCatalog[i].SupportedSchemaVersions...)
	}
	return result
}
