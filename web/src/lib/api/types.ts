import type { paths } from './generated/openapi.ts'

type JsonContent<T> = T extends { 'application/json': infer Content } ? Content : never

export type Health = JsonContent<paths['/healthz']['get']['responses'][200]['content']>

export type Tenant = NonNullable<
  paths['/api/v1/tenants']['get']['responses'][200]['content']['application/json']
>[number]
export type CreateTenantRequest = paths['/api/v1/tenants']['post']['requestBody']['content']['application/json']
export type UpdateTenantRequest = paths['/api/v1/tenants/{id}']['put']['requestBody']['content']['application/json']

export type Upstream = NonNullable<
  paths['/api/v1/upstreams']['get']['responses'][200]['content']['application/json']
>[number]
export type CreateUpstreamRequest = paths['/api/v1/upstreams']['post']['requestBody']['content']['application/json']
export type UpdateUpstreamRequest = paths['/api/v1/upstreams/{id}']['put']['requestBody']['content']['application/json']

export type Policy = NonNullable<
  paths['/api/v1/policies']['get']['responses'][200]['content']['application/json']
>[number]
export type PolicyVersion = NonNullable<
  paths['/api/v1/policies/{id}/versions']['get']['responses'][200]['content']['application/json']
>[number]
export type PolicyTypeDescriptor = NonNullable<
  paths['/api/v1/policy-types']['get']['responses'][200]['content']['application/json']
>[number]
export type CreatePolicyRequest = paths['/api/v1/policies']['post']['requestBody']['content']['application/json']
export type UpdatePolicyRequest = paths['/api/v1/policies/{id}']['put']['requestBody']['content']['application/json']
export type RollbackPolicyRequest =
  paths['/api/v1/policies/{id}/rollback']['post']['requestBody']['content']['application/json']
export type PolicyImportResult =
  paths['/api/v1/policies/import']['post']['responses'][200]['content']['application/json']

export type Evaluation = NonNullable<
  paths['/api/v1/evaluations']['get']['responses'][200]['content']['application/json']
>[number]

export type DependencyGraphRoot = NonNullable<
  paths['/api/v1/dependency-graphs']['get']['responses'][200]['content']['application/json']
>[number]
export type DependencyGraph =
  paths['/api/v1/dependency-graphs/{id}']['get']['responses'][200]['content']['application/json']

export type CacheClearResult =
  paths['/api/v1/cache/decisions']['delete']['responses'][200]['content']['application/json']

export const policyTypes = [
  'cvss_threshold',
  'minimum_age',
  'maximum_age',
  'block_mutable_tag',
  'scorecard',
  'license',
  'license_allowlist',
  'allowlist',
  'namespace_allowlist',
  'blocklist',
] as const

export type PolicyType = (typeof policyTypes)[number]
export type PolicyAction = 'allow' | 'deny'

export type DependencyScope = 'direct' | 'transitive' | 'unknown'
export type DependencyType = 'prod' | 'dev' | 'peer' | 'optional'
export type DependencyUnknownAction = 'warn' | 'deny' | 'skip'

export type PolicyTarget = {
  dependency_scope?: DependencyScope[]
  dependency_types?: DependencyType[]
  on_unknown?: DependencyUnknownAction
}

export type VulnerabilitySeverity = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type CVSSThresholdPolicyConfig = {
  max_cvss?: number
  minimum_severity?: VulnerabilitySeverity
  dry_run?: boolean
}

export type MinimumAgePolicyConfig = {
  min_age_days: number
  exclude_packages?: string[]
  dry_run?: boolean
}

export type MaximumAgePolicyConfig = {
  max_age_days: number
  exclude_packages?: string[]
  dry_run?: boolean
}

export type BlockMutableTagPolicyConfig = {
  tags: string[]
  dry_run?: boolean
}

export type ScorecardUnavailableBehavior = 'deny' | 'skip'

export type ScorecardPolicyConfig = {
  min_score?: number
  checks?: Record<string, number>
  unavailable_scorecard_behavior?: ScorecardUnavailableBehavior
  dry_run?: boolean
}

export type LicensePolicyConfig = {
  licenses: string[]
  dry_run?: boolean
}

export type LicenseAllowlistMissingBehavior = 'deny' | 'skip'

export type LicenseAllowlistPolicyConfig = {
  licenses: string[]
  unlicensed_behavior?: LicenseAllowlistMissingBehavior
  unavailable_metadata_behavior?: LicenseAllowlistMissingBehavior
  dry_run?: boolean
}

export type NamespaceListPolicyConfig = {
  namespaces: string[]
  dry_run?: boolean
}

export type PolicyConfigByType = {
  cvss_threshold: CVSSThresholdPolicyConfig
  minimum_age: MinimumAgePolicyConfig
  maximum_age: MaximumAgePolicyConfig
  block_mutable_tag: BlockMutableTagPolicyConfig
  scorecard: ScorecardPolicyConfig
  license: LicensePolicyConfig
  license_allowlist: LicenseAllowlistPolicyConfig
  allowlist: NamespaceListPolicyConfig
  namespace_allowlist: NamespaceListPolicyConfig
  blocklist: NamespaceListPolicyConfig
}

export type TypedPolicyConfig = PolicyConfigByType[PolicyType]

type TypedEntity<T extends { type: string; config: unknown }> = Omit<T, 'type' | 'config'> &
  {
    [K in PolicyType]: {
      type: K
      config: PolicyConfigByType[K]
    }
  }[PolicyType]

export type TypedPolicy = TypedEntity<Policy>
export type TypedPolicyVersion = TypedEntity<PolicyVersion>

export type PolicyUpsertBase = {
  name: string
  schema_version: number
  priority?: number
  enabled?: boolean
  upstream_id?: string
  target?: PolicyTarget
}

export type PolicyUpsertInput = PolicyUpsertBase &
  {
    [K in PolicyType]: {
      type: K
      action: PolicyAction
      config: PolicyConfigByType[K]
    }
  }[PolicyType]

export type PolicyImportContentType =
  'application/json' | 'application/x-yaml' | 'application/yaml' | 'text/yaml' | 'text/x-yaml'

export type PolicyImportDocument = {
  tenant_id?: string
  policies: PolicyUpsertInput[]
}

export type PolicyImportBody = PolicyImportDocument | string | Uint8Array

export function asTypedPolicy(policy: Policy): TypedPolicy {
  return policy as TypedPolicy
}

export function asTypedPolicyVersion(policy: PolicyVersion): TypedPolicyVersion {
  return policy as TypedPolicyVersion
}
