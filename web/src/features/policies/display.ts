// Policy display helpers format policy records for lists, detail views, and search matching.
import type { TypedPolicy, TypedPolicyVersion, Upstream } from '../../lib/api/index.ts'
import { getPolicyTypeLabel } from './draft.ts'

export type PolicyDisplayRecord = TypedPolicy | TypedPolicyVersion

const timestampFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

export function formatPolicyTimestamp(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? value : timestampFormatter.format(date)
}

export function sortPolicies(a: TypedPolicy, b: TypedPolicy) {
  return a.priority - b.priority || a.name.localeCompare(b.name)
}

export function formatUpstreamOptionLabel(upstream: Upstream) {
  return `${upstream.name} (${upstream.ecosystem.toUpperCase()})`
}

export function formatPolicyScopeLabel(
  policy: PolicyDisplayRecord,
  upstreamsByID: Map<string, Upstream>,
) {
  const upstreamID = policy.upstream_id?.trim()
  if (!upstreamID) {
    return 'Tenant-wide (legacy)'
  }

  const upstream = upstreamsByID.get(upstreamID)
  return upstream ? formatUpstreamOptionLabel(upstream) : `Upstream ${upstreamID}`
}

export function formatPolicyScopeCaption(
  policy: PolicyDisplayRecord,
  upstreamsByID: Map<string, Upstream>,
) {
  const upstreamID = policy.upstream_id?.trim()
  if (!upstreamID) {
    return 'Legacy tenant-wide scope'
  }

  const upstream = upstreamsByID.get(upstreamID)
  return upstream
    ? `Scoped to ${upstream.ecosystem.toUpperCase()} upstream ${upstream.name}`
    : `Scoped to upstream ${upstreamID}`
}

export function getActionTone(action: string) {
  return action === 'deny' ? 'policy-badge-danger' : 'policy-badge-success'
}

export function getEnabledTone(enabled: boolean) {
  return enabled ? 'policy-badge-info' : 'policy-badge-muted'
}

function formatLicenseAllowlistBehaviorLabel(value?: string) {
  return value === 'skip' ? 'Skip this policy' : 'Deny artifact'
}

function summarizeListValues(values: string[]) {
  if (values.length === 0) {
    return 'None'
  }

  const head = values.slice(0, 2).join(', ')
  const suffix = values.length > 2 ? ` +${values.length - 2} more` : ''
  return `${head}${suffix}`
}

export function getPolicyConfigFields(policy: PolicyDisplayRecord): Array<{ label: string; values: string[] }> {
  switch (policy.type) {
    case 'cvss_threshold':
      return [{ label: 'Max CVSS', values: [String(policy.config.max_cvss)] }]
    case 'minimum_age': {
      const fields = [{ label: 'Minimum age', values: [`${policy.config.min_age_days} days`] }]
      if (policy.config.exclude_packages?.length) {
        fields.push({ label: 'Excluded packages', values: policy.config.exclude_packages })
      }
      return fields
    }
    case 'maximum_age': {
      const fields = [{ label: 'Maximum age', values: [`${policy.config.max_age_days} days`] }]
      if (policy.config.exclude_packages?.length) {
        fields.push({ label: 'Excluded packages', values: policy.config.exclude_packages })
      }
      return fields
    }
    case 'block_mutable_tag':
      return [{ label: 'Tags', values: policy.config.tags }]
    case 'scorecard': {
      const fields: Array<{ label: string; values: string[] }> = []
      if (policy.config.min_score !== undefined) {
        fields.push({ label: 'Minimum overall score', values: [String(policy.config.min_score)] })
      }
      if (policy.config.checks && Object.keys(policy.config.checks).length > 0) {
        fields.push({
          label: 'Per-check minimums',
          values: Object.entries(policy.config.checks)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([name, score]) => `${name} >= ${score}`),
        })
      }
      fields.push({
        label: 'When Scorecard unavailable',
        values: [(policy.config.unavailable_scorecard_behavior ?? 'deny') === 'skip' ? 'Skip this policy' : 'Deny artifact'],
      })
      return fields
    }
    case 'license':
      return [{ label: 'Licenses', values: policy.config.licenses }]
    case 'license_allowlist':
      return [
        { label: 'Approved licenses', values: policy.config.licenses },
        ...(policy.schema_version >= 2
          ? [
              {
                label: 'When unlicensed',
                values: [formatLicenseAllowlistBehaviorLabel(policy.config.unlicensed_behavior)],
              },
              {
                label: 'When metadata unavailable',
                values: [formatLicenseAllowlistBehaviorLabel(policy.config.unavailable_metadata_behavior)],
              },
            ]
          : []),
      ]
    case 'allowlist':
      return [{ label: 'Namespaces', values: policy.config.namespaces }]
    case 'namespace_allowlist':
      return [{ label: 'Approved namespaces', values: policy.config.namespaces }]
    case 'blocklist':
      return [{ label: 'Blocked namespaces', values: policy.config.namespaces }]
  }
}

export function getPolicyConfigDetail(policy: PolicyDisplayRecord) {
  const [primaryField, ...extraFields] = getPolicyConfigFields(policy)
  if (!primaryField) {
    return { label: 'Configuration', value: 'No configuration values' }
  }

  const primaryValue =
    primaryField.values.length <= 1 ? primaryField.values[0] ?? 'No value' : summarizeListValues(primaryField.values)

  return {
    label: primaryField.label,
    value: extraFields.length > 0 ? `${primaryValue} • +${extraFields.length} more` : primaryValue,
  }
}

export function matchesPolicySearch(
  policy: TypedPolicy,
  upstreamsByID: Map<string, Upstream>,
  query: string,
) {
  const normalizedQuery = query.trim().toLowerCase()
  if (!normalizedQuery) {
    return true
  }

  const configDetail = getPolicyConfigDetail(policy)
  const searchableFields = [
    policy.name,
    policy.id,
    policy.type,
    getPolicyTypeLabel(policy.type),
    policy.action,
    formatPolicyScopeLabel(policy, upstreamsByID),
    formatPolicyScopeCaption(policy, upstreamsByID),
    configDetail.label,
    configDetail.value,
  ]

  return searchableFields.some((field) => field.toLowerCase().includes(normalizedQuery))
}
