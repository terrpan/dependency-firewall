import type {
  PolicyAction,
  PolicyConfigByType,
  PolicyType,
  PolicyTypeDescriptor,
  PolicyUpsertInput,
  TypedPolicy,
  TypedPolicyVersion,
} from '../../lib/api'

type NumberField = 'max_cvss' | 'min_age_days' | 'max_age_days'
type ListField = 'tags' | 'licenses' | 'namespaces'

type DraftDefinition = {
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
  license: ['deny', 'allow'],
  blocklist: ['deny', 'allow'],
} satisfies Record<PolicyType, PolicyAction[]>

export const policyDraftDefinitions: Record<PolicyType, DraftDefinition> = {
  cvss_threshold: {
    displayName: 'CVSS threshold',
    summary: 'Block all artifacts on the matched upstream when the maximum CVSS score is at or above the configured ceiling.',
    description: 'Uses OSV vulnerability enrichment, applies tenant-wide unless scoped to one upstream, and does not require a package list.',
    defaultPriority: 10,
    numberField: 'max_cvss',
    numberLabel: 'Maximum CVSS score',
    numberDefault: 7,
    numberStep: 0.1,
    numberMin: 0,
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
    description: 'This is the strict fail-closed license policy and should remain a deny rule.',
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

export type PolicyDraftState = {
  type: PolicyType | null
  upstreamId: string
  name: string
  action: PolicyAction
  schemaVersion: string
  priority: string
  enabled: boolean
  numericValue: string
  listValue: string
  excludePackages: string
  dryRun: boolean
}

type PreviewMode = 'preview' | 'strict'

type PolicyRecord = TypedPolicy | TypedPolicyVersion

function parseInteger(value: string): number | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  const parsed = Number(trimmed)
  if (!Number.isInteger(parsed)) {
    return null
  }

  return parsed
}

function parseNumber(value: string): number | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : null
}

export function parseDelimitedValues(value: string): string[] {
  return value
    .split(/\n|,/g)
    .map((item) => item.trim())
    .filter(Boolean)
}

function getDefinition(type: PolicyType) {
  return policyDraftDefinitions[type]
}

function getFallbackActions(type: PolicyType): PolicyAction[] {
  return fallbackActionMap[type]
}

export function getSupportedActions(
  type: PolicyType,
  descriptor?: PolicyTypeDescriptor | null,
): PolicyAction[] {
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
    type === 'block_mutable_tag' ? ['oci'] : type === 'cvss_threshold' || type === 'minimum_age' || type === 'maximum_age' || type === 'license' || type === 'license_allowlist' ? ['npm'] : ['npm', 'oci']
  const requiredCapabilities =
    type === 'cvss_threshold'
      ? ['vulnerability_lookup']
      : type === 'minimum_age' || type === 'maximum_age'
        ? ['publish_time']
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
    supported_schema_versions: [1],
    current_schema_version: 1,
    supported_ecosystems: supportedEcosystems,
    required_capabilities: requiredCapabilities,
  }
}

export function getPolicyTypeLabel(type: PolicyType) {
  return getDefinition(type).displayName
}

export function createEmptyPolicyDraft(): PolicyDraftState {
  return {
    type: null,
    upstreamId: '',
    name: '',
    action: 'deny',
    schemaVersion: '1',
    priority: '',
    enabled: true,
    numericValue: '',
    listValue: '',
    excludePackages: '',
    dryRun: false,
  }
}

export function createPolicyDraftForType(
  type: PolicyType,
  descriptor?: PolicyTypeDescriptor | null,
): PolicyDraftState {
  const definition = getDefinition(type)
  const supportedActions = getSupportedActions(type, descriptor)

  return {
    type,
    upstreamId: '',
    name: '',
    action: supportedActions[0] ?? 'deny',
    schemaVersion: String(descriptor?.current_schema_version ?? 1),
    priority: String(definition.defaultPriority),
    enabled: true,
    numericValue:
      definition.numberDefault === undefined ? '' : String(definition.numberDefault),
    listValue: definition.listDefault?.join('\n') ?? '',
    excludePackages: '',
    dryRun: false,
  }
}

export function createPolicyDraftFromPolicy(policy: PolicyRecord): PolicyDraftState {
  const action: PolicyAction = policy.action === 'allow' ? 'allow' : 'deny'
  const baseDraft = {
    type: policy.type,
    upstreamId: policy.upstream_id ?? '',
    name: policy.name,
    action,
    schemaVersion: String(policy.schema_version),
    priority: String(policy.priority),
    enabled: policy.enabled,
    numericValue: '',
    listValue: '',
    excludePackages: '',
    dryRun: Boolean(policy.config.dry_run),
  } satisfies PolicyDraftState

  switch (policy.type) {
    case 'cvss_threshold':
      return {
        ...baseDraft,
        numericValue: String(policy.config.max_cvss),
      }
    case 'minimum_age':
      return {
        ...baseDraft,
        numericValue: String(policy.config.min_age_days),
        excludePackages: (policy.config.exclude_packages ?? []).join('\n'),
      }
    case 'maximum_age':
      return {
        ...baseDraft,
        numericValue: String(policy.config.max_age_days),
        excludePackages: (policy.config.exclude_packages ?? []).join('\n'),
      }
    case 'block_mutable_tag':
      return {
        ...baseDraft,
        listValue: policy.config.tags.join('\n'),
      }
    case 'license':
      return {
        ...baseDraft,
        listValue: policy.config.licenses.join('\n'),
      }
    case 'license_allowlist':
      return {
        ...baseDraft,
        listValue: policy.config.licenses.join('\n'),
      }
    case 'allowlist':
      return {
        ...baseDraft,
        listValue: policy.config.namespaces.join('\n'),
      }
    case 'namespace_allowlist':
      return {
        ...baseDraft,
        listValue: policy.config.namespaces.join('\n'),
      }
    case 'blocklist':
      return {
        ...baseDraft,
        listValue: policy.config.namespaces.join('\n'),
      }
  }
}

function resolvePriority(
  draft: PolicyDraftState,
  type: PolicyType,
  mode: PreviewMode,
): number {
  const definition = getDefinition(type)
  const parsed = parseInteger(draft.priority)

  if (parsed !== null) {
    return parsed
  }

  if (mode === 'preview') {
    return definition.defaultPriority
  }

  throw new Error('Priority must be a whole number.')
}

function resolveSchemaVersion(draft: PolicyDraftState, mode: PreviewMode): number {
  const parsed = parseInteger(draft.schemaVersion)

  if (parsed !== null && parsed > 0) {
    return parsed
  }

  if (mode === 'preview') {
    return 1
  }

  throw new Error('Schema version must be a positive whole number.')
}

function resolveName(draft: PolicyDraftState, type: PolicyType, mode: PreviewMode): string {
  const trimmed = draft.name.trim()
  if (trimmed) {
    return trimmed
  }

  if (mode === 'preview') {
    return `${type}-policy`
  }

  throw new Error('Name is required.')
}

function resolveNumberValue(
  draft: PolicyDraftState,
  type: PolicyType,
  mode: PreviewMode,
): number {
  const definition = getDefinition(type)
  const parsed = parseNumber(draft.numericValue)

  if (parsed !== null) {
    return parsed
  }

  if (mode === 'preview' && definition.numberDefault !== undefined) {
    return definition.numberDefault
  }

  throw new Error(`${definition.numberLabel ?? 'Config value'} is required.`)
}

function resolveListValue(
  draft: PolicyDraftState,
  type: PolicyType,
  mode: PreviewMode,
): string[] {
  const definition = getDefinition(type)
  const values = parseDelimitedValues(draft.listValue)

  if (values.length > 0) {
    return values
  }

  if (mode === 'preview' && definition.listDefault && definition.listDefault.length > 0) {
    return definition.listDefault
  }

  throw new Error(`${definition.listLabel ?? 'List values'} must include at least one item.`)
}

function maybeIncludeDryRun<TConfig extends { dry_run?: boolean }>(
  config: TConfig,
  draft: PolicyDraftState,
): TConfig {
  if (draft.dryRun) {
    config.dry_run = true
  }

  return config
}

function buildConfig(
  draft: PolicyDraftState,
  type: PolicyType,
  mode: PreviewMode,
): PolicyConfigByType[PolicyType] {
  switch (type) {
    case 'cvss_threshold': {
      return maybeIncludeDryRun<PolicyConfigByType['cvss_threshold']>(
        {
          max_cvss: resolveNumberValue(draft, type, mode),
        },
        draft,
      )
    }
    case 'minimum_age': {
      const config = maybeIncludeDryRun<PolicyConfigByType['minimum_age']>(
        {
          min_age_days: resolveNumberValue(draft, type, mode),
        },
        draft,
      )
      const excludePackages = parseDelimitedValues(draft.excludePackages)
      if (excludePackages.length > 0) {
        config.exclude_packages = excludePackages
      }
      return config
    }
    case 'maximum_age': {
      const config = maybeIncludeDryRun<PolicyConfigByType['maximum_age']>(
        {
          max_age_days: resolveNumberValue(draft, type, mode),
        },
        draft,
      )
      const excludePackages = parseDelimitedValues(draft.excludePackages)
      if (excludePackages.length > 0) {
        config.exclude_packages = excludePackages
      }
      return config
    }
    case 'block_mutable_tag': {
      return maybeIncludeDryRun<PolicyConfigByType['block_mutable_tag']>(
        {
          tags: resolveListValue(draft, type, mode),
        },
        draft,
      )
    }
    case 'license': {
      return maybeIncludeDryRun<PolicyConfigByType['license']>(
        {
          licenses: resolveListValue(draft, type, mode),
        },
        draft,
      )
    }
    case 'license_allowlist': {
      return maybeIncludeDryRun<PolicyConfigByType['license_allowlist']>(
        {
          licenses: resolveListValue(draft, type, mode),
        },
        draft,
      )
    }
    case 'allowlist': {
      return maybeIncludeDryRun<PolicyConfigByType['allowlist']>(
        {
          namespaces: resolveListValue(draft, type, mode),
        },
        draft,
      )
    }
    case 'namespace_allowlist': {
      return maybeIncludeDryRun<PolicyConfigByType['namespace_allowlist']>(
        {
          namespaces: resolveListValue(draft, type, mode),
        },
        draft,
      )
    }
    case 'blocklist': {
      return maybeIncludeDryRun<PolicyConfigByType['blocklist']>(
        {
          namespaces: resolveListValue(draft, type, mode),
        },
        draft,
      )
    }
  }
}

function buildPolicyInput(
  draft: PolicyDraftState,
  descriptor?: PolicyTypeDescriptor | null,
  mode: PreviewMode = 'strict',
): PolicyUpsertInput | null {
  if (!draft.type) {
    return null
  }

  const supportedActions = getSupportedActions(draft.type, descriptor)
  const action = supportedActions.includes(draft.action) ? draft.action : supportedActions[0] ?? 'deny'

  const name = resolveName(draft, draft.type, mode)
  const schemaVersion = resolveSchemaVersion(draft, mode)
  const priority = resolvePriority(draft, draft.type, mode)
  const enabled = draft.enabled
  const upstreamID = draft.upstreamId.trim()
  const baseInput = upstreamID ? { upstream_id: upstreamID } : {}

  switch (draft.type) {
    case 'cvss_threshold':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['cvss_threshold'],
      }
    case 'minimum_age':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['minimum_age'],
      }
    case 'maximum_age':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['maximum_age'],
      }
    case 'block_mutable_tag':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['block_mutable_tag'],
      }
    case 'license':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['license'],
      }
    case 'license_allowlist':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['license_allowlist'],
      }
    case 'allowlist':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['allowlist'],
      }
    case 'namespace_allowlist':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['namespace_allowlist'],
      }
    case 'blocklist':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, mode) as PolicyConfigByType['blocklist'],
      }
  }
}

export function buildPolicyDraftPreview(
  draft: PolicyDraftState,
  descriptor?: PolicyTypeDescriptor | null,
): PolicyUpsertInput | null {
  return buildPolicyInput(draft, descriptor, 'preview')
}

export function buildPolicyDraftInput(
  draft: PolicyDraftState,
  descriptor?: PolicyTypeDescriptor | null,
): PolicyUpsertInput {
  const input = buildPolicyInput(draft, descriptor, 'strict')
  if (!input) {
    throw new Error('Choose a policy type.')
  }

  return input
}

export function validatePolicyDraft(
  draft: PolicyDraftState,
  descriptor?: PolicyTypeDescriptor | null,
): string[] {
  try {
    buildPolicyDraftInput(draft, descriptor)
    return []
  } catch (error) {
    return [error instanceof Error ? error.message : 'Policy draft is incomplete.']
  }
}

export function isPolicyDryRun(policy: PolicyRecord): boolean {
  return Boolean(policy.config.dry_run)
}

function quoteYamlString(value: string): string {
  return JSON.stringify(value)
}

function formatYamlScalar(value: string | number | boolean | null): string {
  if (typeof value === 'string') {
    return quoteYamlString(value)
  }

  if (value === null) {
    return 'null'
  }

  return String(value)
}

function isYamlObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function formatYamlEntry(key: string, value: unknown, indent: number): string {
  const padding = ' '.repeat(indent)

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return `${padding}${key}: []`
    }

    return `${padding}${key}:\n${formatYamlValue(value, indent + 2)}`
  }

  if (isYamlObject(value)) {
    const entries = Object.entries(value)
    if (entries.length === 0) {
      return `${padding}${key}: {}`
    }

    return `${padding}${key}:\n${formatYamlValue(value, indent + 2)}`
  }

  return `${padding}${key}: ${formatYamlScalar((value ?? null) as string | number | boolean | null)}`
}

function formatYamlValue(value: unknown, indent = 0): string {
  const padding = ' '.repeat(indent)

  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (Array.isArray(item) || isYamlObject(item)) {
          const rendered = formatYamlValue(item, indent + 2)
          const [firstLine, ...rest] = rendered.split('\n')
          return [`${padding}- ${firstLine.trimStart()}`, ...rest].join('\n')
        }

        return `${padding}- ${formatYamlScalar((item ?? null) as string | number | boolean | null)}`
      })
      .join('\n')
  }

  if (isYamlObject(value)) {
    return Object.entries(value)
      .map(([key, item]) => formatYamlEntry(key, item, indent))
      .join('\n')
  }

  return `${padding}${formatYamlScalar((value ?? null) as string | number | boolean | null)}`
}

export function formatPolicyDraftJsonPreview(policy: PolicyUpsertInput | null): string {
  return JSON.stringify(
    policy ?? { message: 'Select a policy type to generate the JSON preview.' },
    null,
    2,
  )
}

function buildPolicyRecordPreview(policy: PolicyRecord): PolicyUpsertInput {
  const action: PolicyAction = policy.action === 'allow' ? 'allow' : 'deny'
  const basePreview = {
    ...(policy.upstream_id ? { upstream_id: policy.upstream_id } : {}),
    name: policy.name,
    action,
    schema_version: policy.schema_version,
    priority: policy.priority,
    enabled: policy.enabled,
  }

  switch (policy.type) {
    case 'cvss_threshold':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'minimum_age':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'maximum_age':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'block_mutable_tag':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'license':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'license_allowlist':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'allowlist':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'namespace_allowlist':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
    case 'blocklist':
      return {
        ...basePreview,
        type: policy.type,
        config: policy.config,
      }
  }
}

export function formatPolicyRecordJsonPreview(policy: PolicyRecord | null): string {
  return JSON.stringify(
    policy ? buildPolicyRecordPreview(policy) : { message: 'Select a policy version to generate the JSON preview.' },
    null,
    2,
  )
}

export function formatPolicyDraftYamlPreview(
  tenantId: string | null,
  policy: PolicyUpsertInput | null,
): string {
  return formatYamlValue({
    tenant_id: tenantId ?? 'tenant-id',
    policies: policy ? [policy] : [],
  })
}

export function formatPolicyRecordYamlPreview(policy: PolicyRecord | null): string {
  return formatYamlValue(
    policy ? buildPolicyRecordPreview(policy) : { message: 'Select a policy version to generate the YAML preview.' },
  )
}

function summarizeItems(label: string, items: string[]) {
  if (items.length === 0) {
    return label
  }

  const head = items.slice(0, 3).join(', ')
  const suffix = items.length > 3 ? ` +${items.length - 3} more` : ''
  return `${label}: ${head}${suffix}`
}

export function summarizePolicyConfig(policy: PolicyRecord): string {
  switch (policy.type) {
    case 'cvss_threshold': {
      return `Max CVSS ${policy.config.max_cvss}${policy.config.dry_run ? ' • dry run' : ''}`
    }
    case 'minimum_age': {
      const excludeCount = policy.config.exclude_packages?.length ?? 0
      return `Min age ${policy.config.min_age_days}d${excludeCount ? ` • ${excludeCount} exclusions` : ''}${policy.config.dry_run ? ' • dry run' : ''}`
    }
    case 'maximum_age': {
      const excludeCount = policy.config.exclude_packages?.length ?? 0
      return `Max age ${policy.config.max_age_days}d${excludeCount ? ` • ${excludeCount} exclusions` : ''}${policy.config.dry_run ? ' • dry run' : ''}`
    }
    case 'block_mutable_tag': {
      return summarizeItems('Tags', policy.config.tags)
    }
    case 'license': {
      return `${summarizeItems('Licenses', policy.config.licenses)}${policy.config.dry_run ? ' • dry run' : ''}`
    }
    case 'license_allowlist': {
      return `${summarizeItems('Approved licenses', policy.config.licenses)}${policy.config.dry_run ? ' • dry run' : ''}`
    }
    case 'allowlist': {
      return `${summarizeItems('Namespaces', policy.config.namespaces)}${policy.config.dry_run ? ' • dry run' : ''}`
    }
    case 'namespace_allowlist': {
      return `${summarizeItems('Approved namespaces', policy.config.namespaces)}${policy.config.dry_run ? ' • dry run' : ''}`
    }
    case 'blocklist': {
      return `${summarizeItems('Blocked namespaces', policy.config.namespaces)}${policy.config.dry_run ? ' • dry run' : ''}`
    }
  }
}
