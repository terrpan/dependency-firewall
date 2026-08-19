import type { PolicyAction, PolicyType, PolicyTypeDescriptor } from '../../lib/api'

export type NumberField = 'max_cvss' | 'min_age_days' | 'max_age_days' | 'min_score'
export type ListField = 'tags' | 'licenses' | 'namespaces' | 'checks'

export type DraftDefinition = {
  displayName: string
  summary: string
  description: string
  defaultPriority: number
  numberField?: NumberField
  numberLabel?: string
  numberDefault?: number
  numberStep?: number
  numberMin?: number
  listField?: ListField
  listLabel?: string
  listDefault?: string[]
  listPlaceholder?: string
  supportsExcludePackages?: boolean
}

const fallbackActionMap = {
  allowlist: ['allow'],
  namespace_allowlist: ['deny'],
  license_allowlist: ['deny'],
  cvss_threshold: ['deny', 'allow'],
  minimum_age: ['deny', 'allow'],
  maximum_age: ['deny', 'allow'],
  block_mutable_tag: ['deny', 'allow'],
  scorecard: ['deny'],
  license: ['deny', 'allow'],
  blocklist: ['deny', 'allow'],
} satisfies Record<PolicyType, PolicyAction[]>

export const policyDraftDefinitions: Record<PolicyType, DraftDefinition> = {
  cvss_threshold: {
    displayName: 'Vulnerability threshold',
    summary: 'Deny artifacts when CVSS score or vulnerability severity meets the configured threshold.',
    description: 'Uses OSV vulnerability enrichment. Configure a maximum CVSS score, a minimum severity, or both.',
    numberField: 'max_cvss',
    numberLabel: 'Maximum CVSS score (optional)',
    numberDefault: 7,
    numberStep: 0.1,
    numberMin: 0,
    defaultPriority: 10,
  },
  minimum_age: {
    displayName: 'Minimum age',
    summary: 'Deny brand-new artifacts until they have existed for a minimum number of days.',
    description: 'Useful for supply-chain cooling-off periods on newly published dependencies.',
    defaultPriority: 20,
    numberField: 'min_age_days',
    numberLabel: 'Minimum age in days',
    numberDefault: 7,
    numberStep: 1,
    numberMin: 0,
    supportsExcludePackages: true,
  },
  maximum_age: {
    displayName: 'Maximum age',
    summary: 'Deny artifacts that are older than an acceptable maintenance window.',
    description: 'Useful for flagging stale packages or images that are no longer maintained.',
    defaultPriority: 25,
    numberField: 'max_age_days',
    numberLabel: 'Maximum age in days',
    numberDefault: 730,
    numberStep: 1,
    numberMin: 0,
    supportsExcludePackages: true,
  },
  block_mutable_tag: {
    displayName: 'Block mutable tag',
    summary: 'Deny OCI artifacts that use mutable tags such as latest or dev.',
    description: 'Encourages immutable digests or specific versions for OCI pulls.',
    defaultPriority: 15,
    listField: 'tags',
    listLabel: 'Mutable tags to block',
    listDefault: ['latest', 'dev'],
    listPlaceholder: 'latest\ndev',
  },
  scorecard: {
    displayName: 'OpenSSF Scorecard',
    summary:
      'Deny npm artifacts when the source repository Scorecard falls below the top-level score threshold, one or more named check thresholds, or both.',
    description:
      'Uses npm repository metadata plus hosted Scorecard results. Configure the top-level Scorecard score, named check minimums, and how the policy behaves when Scorecard data or specific checks are unavailable.',
    defaultPriority: 15,
    numberField: 'min_score',
    numberLabel: 'Minimum overall Scorecard score (optional)',
    numberDefault: 7,
    numberStep: 0.1,
    numberMin: 0,
    listField: 'checks',
    listLabel: 'Minimum named check scores (optional)',
    listPlaceholder: 'binary-artifacts=10\nbranch-protection=7',
  },
  license: {
    displayName: 'License match',
    summary: 'Match artifacts whose declared licenses include any configured SPDX identifier.',
    description: 'Use targeted deny or warn rules for copyleft or otherwise restricted licenses.',
    defaultPriority: 30,
    listField: 'licenses',
    listLabel: 'Licenses to match',
    listDefault: ['GPL-3.0-only', 'AGPL-3.0-only'],
    listPlaceholder: 'GPL-3.0-only\nAGPL-3.0-only',
  },
  license_allowlist: {
    displayName: 'License allowlist',
    summary: 'Deny artifacts unless all declared licenses are part of an approved SPDX list.',
    description:
      'This is the strict approved-license policy and should remain a deny rule, with configurable handling for unlicensed packages and unavailable metadata.',
    defaultPriority: 30,
    listField: 'licenses',
    listLabel: 'Approved licenses',
    listDefault: ['MIT', 'Apache-2.0', 'BSD-3-Clause'],
    listPlaceholder: 'MIT\nApache-2.0\nBSD-3-Clause',
  },
  allowlist: {
    displayName: 'Namespace allow match',
    summary: 'Allow-match trusted namespaces without overriding later deny rules.',
    description: 'Use this when you want explicit positive matches for internal namespaces.',
    defaultPriority: 5,
    listField: 'namespaces',
    listLabel: 'Trusted namespaces',
    listDefault: ['internal', 'mycompany'],
    listPlaceholder: 'internal\nmycompany',
  },
  namespace_allowlist: {
    displayName: 'Namespace allowlist',
    summary: 'Deny artifacts whose namespace is outside the approved namespace set.',
    description: 'This is the strict fail-closed namespace policy and should remain a deny rule.',
    defaultPriority: 10,
    listField: 'namespaces',
    listLabel: 'Approved namespaces',
    listDefault: ['library', 'docker'],
    listPlaceholder: 'library\ndocker',
  },
  blocklist: {
    displayName: 'Namespace blocklist',
    summary: 'Deny artifacts from explicitly blocked namespaces.',
    description: 'Use this to block known untrusted npm scopes or OCI registries and orgs.',
    defaultPriority: 30,
    listField: 'namespaces',
    listLabel: 'Blocked namespaces',
    listDefault: ['evil-corp'],
    listPlaceholder: 'evil-corp',
  },
}

export function getDefinition(type: PolicyType) {
  return policyDraftDefinitions[type]
}

function getFallbackActions(type: PolicyType): PolicyAction[] {
  return fallbackActionMap[type]
}

export function getSupportedActions(type: PolicyType, descriptor?: PolicyTypeDescriptor | null): PolicyAction[] {
  const supportedActions = descriptor?.supported_actions?.filter(
    (action): action is PolicyAction => action === 'allow' || action === 'deny',
  )

  if (supportedActions && supportedActions.length > 0) {
    return supportedActions
  }

  return getFallbackActions(type)
}

export function createFallbackPolicyTypeDescriptor(type: PolicyType): PolicyTypeDescriptor {
  const definition = getDefinition(type)
  const supportedEcosystems =
    type === 'block_mutable_tag'
      ? ['oci']
      : type === 'cvss_threshold' ||
          type === 'minimum_age' ||
          type === 'maximum_age' ||
          type === 'scorecard' ||
          type === 'license' ||
          type === 'license_allowlist'
        ? ['npm']
        : ['npm', 'oci']
  const requiredCapabilities =
    type === 'cvss_threshold'
      ? ['vulnerability_lookup']
      : type === 'minimum_age' || type === 'maximum_age'
        ? ['publish_time']
        : type === 'scorecard'
          ? ['scorecard_lookup']
          : type === 'license' || type === 'license_allowlist'
            ? ['licenses']
            : type === 'block_mutable_tag'
              ? ['manifest_digest_lookup']
              : []

  return {
    type,
    summary: definition.summary,
    description: definition.description,
    help: definition.description,
    example: `${type}: see control-plane docs`,
    supported_actions: getFallbackActions(type),
    supported_schema_versions: type === 'license_allowlist' ? [1, 2] : [1],
    current_schema_version: type === 'license_allowlist' ? 2 : 1,
    supported_ecosystems: supportedEcosystems,
    required_capabilities: requiredCapabilities,
  }
}

export function getPolicyTypeLabel(type: PolicyType) {
  return getDefinition(type).displayName
}
