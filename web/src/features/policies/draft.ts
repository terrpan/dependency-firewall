import type {
  DependencyScope,
  DependencyType,
  DependencyUnknownAction,
  LicenseAllowlistMissingBehavior,
  PolicyTarget,
  PolicyAction,
  PolicyConfigByType,
  ScorecardUnavailableBehavior,
  PolicyType,
  PolicyTypeDescriptor,
  PolicyUpsertBase,
  PolicyUpsertInput,
  TypedPolicy,
  TypedPolicyVersion,
  VulnerabilitySeverity,
} from '../../lib/api'
import { getDefinition, getSupportedActions } from './draftDefinitions'
import {
  formatScorecardThresholds,
  parseDelimitedValues,
  parseInteger,
  parseNumber,
  parseScorecardThresholds,
} from './draftParsing'

export {
  createFallbackPolicyTypeDescriptor,
  getPolicyTypeLabel,
  getSupportedActions,
  policyDraftDefinitions,
} from './draftDefinitions'
export { parseDelimitedValues, parseScorecardThresholds } from './draftParsing'

export type PolicyDraftState = {
  type: PolicyType | null
  upstreamId: string
  name: string
  action: PolicyAction
  schemaVersion: string
  priority: string
  enabled: boolean
  useCVSSThreshold: boolean
  useMinimumSeverity: boolean
  numericValue: string
  minimumSeverity: VulnerabilitySeverity | ''
  listValue: string
  excludePackages: string
  dryRun: boolean
  unlicensedBehavior: LicenseAllowlistMissingBehavior
  unavailableMetadataBehavior: LicenseAllowlistMissingBehavior
  scorecardUnavailableBehavior: ScorecardUnavailableBehavior
  targetEnabled: boolean
  targetDependencyScopes: DependencyScope[]
  targetDependencyTypes: DependencyType[]
  targetOnUnknown: DependencyUnknownAction
}

type PreviewMode = 'preview' | 'strict'

type PolicyRecord = TypedPolicy | TypedPolicyVersion

const dependencyScopes = ['direct', 'transitive', 'unknown'] satisfies DependencyScope[]
const dependencyTypes = ['prod', 'dev', 'peer', 'optional'] satisfies DependencyType[]
const unknownActions = ['warn', 'deny', 'skip'] satisfies DependencyUnknownAction[]

export function createEmptyPolicyDraft(): PolicyDraftState {
  return {
    type: null,
    upstreamId: '',
    name: '',
    action: 'deny',
    schemaVersion: '1',
    priority: '',
    enabled: true,
    useCVSSThreshold: false,
    useMinimumSeverity: false,
    numericValue: '',
    minimumSeverity: '',
    listValue: '',
    excludePackages: '',
    dryRun: false,
    unlicensedBehavior: 'deny',
    unavailableMetadataBehavior: 'deny',
    scorecardUnavailableBehavior: 'deny',
    targetEnabled: false,
    targetDependencyScopes: [],
    targetDependencyTypes: [],
    targetOnUnknown: 'warn',
  }
}

export function createPolicyDraftForType(type: PolicyType, descriptor?: PolicyTypeDescriptor | null): PolicyDraftState {
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
    useCVSSThreshold: type === 'cvss_threshold',
    useMinimumSeverity: false,
    numericValue: definition.numberDefault === undefined ? '' : String(definition.numberDefault),
    minimumSeverity: '',
    listValue: definition.listDefault?.join('\n') ?? '',
    excludePackages: '',
    dryRun: false,
    unlicensedBehavior: 'deny',
    unavailableMetadataBehavior: 'deny',
    scorecardUnavailableBehavior: 'deny',
    targetEnabled: false,
    targetDependencyScopes: [],
    targetDependencyTypes: [],
    targetOnUnknown: 'warn',
  }
}

export function createPolicyDraftFromPolicy(policy: PolicyRecord): PolicyDraftState {
  const action: PolicyAction = policy.action === 'allow' ? 'allow' : 'deny'
  const target = normalizePolicyTarget(policy.target)
  const baseDraft = {
    type: policy.type,
    upstreamId: policy.upstream_id ?? '',
    name: policy.name,
    action,
    schemaVersion: String(policy.schema_version),
    priority: String(policy.priority),
    enabled: policy.enabled,
    useCVSSThreshold: false,
    useMinimumSeverity: false,
    numericValue: '',
    minimumSeverity: '',
    listValue: '',
    excludePackages: '',
    dryRun: Boolean(policy.config.dry_run),
    unlicensedBehavior: policy.type === 'license_allowlist' ? (policy.config.unlicensed_behavior ?? 'deny') : 'deny',
    unavailableMetadataBehavior:
      policy.type === 'license_allowlist' ? (policy.config.unavailable_metadata_behavior ?? 'deny') : 'deny',
    scorecardUnavailableBehavior:
      policy.type === 'scorecard' ? (policy.config.unavailable_scorecard_behavior ?? 'deny') : 'deny',
    targetEnabled: Boolean(target),
    targetDependencyScopes: target?.dependency_scope ?? [],
    targetDependencyTypes: target?.dependency_types ?? [],
    targetOnUnknown: target?.on_unknown ?? 'warn',
  } satisfies PolicyDraftState

  switch (policy.type) {
    case 'cvss_threshold':
      return {
        ...baseDraft,
        useCVSSThreshold: policy.config.max_cvss !== undefined,
        useMinimumSeverity: policy.config.minimum_severity !== undefined,
        numericValue: policy.config.max_cvss === undefined ? '' : String(policy.config.max_cvss),
        minimumSeverity: policy.config.minimum_severity ?? '',
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
    case 'scorecard':
      return {
        ...baseDraft,
        numericValue: policy.config.min_score === undefined ? '' : String(policy.config.min_score),
        listValue: formatScorecardThresholds(policy.config.checks),
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

function normalizePolicyTarget(target: PolicyRecord['target']): PolicyTarget | undefined {
  if (!target) {
    return undefined
  }

  const dependency_scope = (target.dependency_scope ?? []).filter((value): value is DependencyScope =>
    dependencyScopes.includes(value as DependencyScope),
  )
  const dependency_types = (target.dependency_types ?? []).filter((value): value is DependencyType =>
    dependencyTypes.includes(value as DependencyType),
  )
  const on_unknown = unknownActions.includes(target.on_unknown as DependencyUnknownAction)
    ? (target.on_unknown as DependencyUnknownAction)
    : 'warn'

  return {
    ...(dependency_scope.length > 0 ? { dependency_scope } : {}),
    ...(dependency_types.length > 0 ? { dependency_types } : {}),
    on_unknown,
  }
}

function resolvePriority(draft: PolicyDraftState, type: PolicyType, mode: PreviewMode): number {
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

function resolveNumberValue(draft: PolicyDraftState, type: PolicyType, mode: PreviewMode): number {
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

function resolveListValue(draft: PolicyDraftState, type: PolicyType, mode: PreviewMode): string[] {
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

function resolveOptionalNumberValue(value: string): number | null {
  const parsed = parseNumber(value)
  return parsed === null ? null : parsed
}

function maybeIncludeDryRun<TConfig extends { dry_run?: boolean }>(config: TConfig, draft: PolicyDraftState): TConfig {
  if (draft.dryRun) {
    config.dry_run = true
  }

  return config
}

function licenseAllowlistSupportsMissingBehavior(schemaVersion: number): boolean {
  return schemaVersion >= 2
}

function buildConfig(
  draft: PolicyDraftState,
  type: PolicyType,
  schemaVersion: number,
  mode: PreviewMode,
): PolicyConfigByType[PolicyType] {
  switch (type) {
    case 'cvss_threshold': {
      const config = maybeIncludeDryRun<PolicyConfigByType['cvss_threshold']>({}, draft)

      if (!draft.useCVSSThreshold && !draft.useMinimumSeverity) {
        throw new Error('Enable CVSS score, minimum severity, or both.')
      }

      if (draft.useCVSSThreshold) {
        const maxCVSS = resolveOptionalNumberValue(draft.numericValue)
        if (maxCVSS === null) {
          throw new Error('Maximum CVSS score is required when CVSS threshold is enabled.')
        }
        config.max_cvss = maxCVSS
      }

      if (draft.useMinimumSeverity) {
        if (!draft.minimumSeverity) {
          throw new Error('Minimum severity is required when severity threshold is enabled.')
        }
        config.minimum_severity = draft.minimumSeverity
      }

      return config
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
    case 'scorecard': {
      const minScore = resolveOptionalNumberValue(draft.numericValue)
      const checks = parseScorecardThresholds(draft.listValue)
      const defaultMinScore = getDefinition(type).numberDefault ?? null
      const effectiveMinScore =
        minScore === null && mode === 'preview' && Object.keys(checks).length === 0 ? defaultMinScore : minScore

      if (effectiveMinScore === null && Object.keys(checks).length === 0) {
        throw new Error('Configure an overall score, one or more check minimums, or both.')
      }

      const config = maybeIncludeDryRun<PolicyConfigByType['scorecard']>(
        {
          unavailable_scorecard_behavior: draft.scorecardUnavailableBehavior,
        },
        draft,
      )
      if (effectiveMinScore !== null) {
        config.min_score = effectiveMinScore
      }
      if (Object.keys(checks).length > 0) {
        config.checks = checks
      }
      return config
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
      const config = maybeIncludeDryRun<PolicyConfigByType['license_allowlist']>(
        {
          licenses: resolveListValue(draft, type, mode),
        },
        draft,
      )
      if (licenseAllowlistSupportsMissingBehavior(schemaVersion)) {
        config.unlicensed_behavior = draft.unlicensedBehavior
        config.unavailable_metadata_behavior = draft.unavailableMetadataBehavior
      }
      return config
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
  const action = supportedActions.includes(draft.action) ? draft.action : (supportedActions[0] ?? 'deny')

  const name = resolveName(draft, draft.type, mode)
  const schemaVersion = resolveSchemaVersion(draft, mode)
  const priority = resolvePriority(draft, draft.type, mode)
  const enabled = draft.enabled
  const upstreamID = draft.upstreamId.trim()
  const target = buildPolicyTarget(draft)
  const baseInput: Partial<Pick<PolicyUpsertBase, 'upstream_id' | 'target'>> = {
    ...(upstreamID ? { upstream_id: upstreamID } : {}),
    ...(target ? { target } : {}),
  }

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
        config: buildConfig(draft, draft.type, schemaVersion, mode),
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['minimum_age'],
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['maximum_age'],
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['block_mutable_tag'],
      }
    case 'scorecard':
      return {
        ...baseInput,
        name,
        type: draft.type,
        action,
        schema_version: schemaVersion,
        priority,
        enabled,
        config: buildConfig(draft, draft.type, schemaVersion, mode),
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['license'],
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['license_allowlist'],
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['allowlist'],
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['namespace_allowlist'],
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
        config: buildConfig(draft, draft.type, schemaVersion, mode) as PolicyConfigByType['blocklist'],
      }
  }
}

function buildPolicyTarget(draft: PolicyDraftState): PolicyTarget | undefined {
  if (!draft.targetEnabled) {
    return undefined
  }

  return {
    ...(draft.targetDependencyScopes.length > 0 ? { dependency_scope: draft.targetDependencyScopes } : {}),
    ...(draft.targetDependencyTypes.length > 0 ? { dependency_types: draft.targetDependencyTypes } : {}),
    on_unknown: draft.targetOnUnknown,
  }
}

export function buildPolicyDraftPreview(
  draft: PolicyDraftState,
  descriptor?: PolicyTypeDescriptor | null,
): PolicyUpsertInput | null {
  try {
    return buildPolicyInput(draft, descriptor, 'preview')
  } catch {
    return null
  }
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

export function validatePolicyDraft(draft: PolicyDraftState, descriptor?: PolicyTypeDescriptor | null): string[] {
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
  return JSON.stringify(policy ?? { message: 'Select a policy type to generate the JSON preview.' }, null, 2)
}

function buildPolicyRecordPreview(policy: PolicyRecord): PolicyUpsertInput {
  const action: PolicyAction = policy.action === 'allow' ? 'allow' : 'deny'
  const target = normalizePolicyTarget(policy.target)
  const basePreview = {
    ...(policy.upstream_id ? { upstream_id: policy.upstream_id } : {}),
    ...(target ? { target } : {}),
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
    case 'scorecard':
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

export function formatPolicyDraftYamlPreview(tenantId: string | null, policy: PolicyUpsertInput | null): string {
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
