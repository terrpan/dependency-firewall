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

export function formatPolicyScopeLabel(policy: PolicyDisplayRecord, upstreamsByID: Map<string, Upstream>) {
  const upstreamID = policy.upstream_id?.trim()
  if (!upstreamID) {
    return 'Tenant-wide (legacy)'
  }

  const upstream = upstreamsByID.get(upstreamID)
  return upstream ? formatUpstreamOptionLabel(upstream) : `Upstream ${upstreamID}`
}

export function formatPolicyScopeCaption(policy: PolicyDisplayRecord, upstreamsByID: Map<string, Upstream>) {
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

function summarizeRuleValues(values: string[]) {
  return values.length > 0 ? summarizeListValues(values) : 'none configured'
}

function actionVerb(policy: PolicyDisplayRecord) {
  const hypothetical = !policy.enabled || policy.config.dry_run === true
  if (policy.action === 'allow') {
    return hypothetical ? 'Would record an allow match for' : 'Record an allow match for'
  }
  return hypothetical ? 'Would deny' : 'Deny'
}

function formatSeverityLabel(value: string) {
  const normalized = value.trim().toLowerCase()
  if (normalized === 'medium') {
    return 'Moderate'
  }
  return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : value
}

export function getPolicyConfigFields(policy: PolicyDisplayRecord): Array<{ label: string; values: string[] }> {
  switch (policy.type) {
    case 'cvss_threshold': {
      const fields: Array<{ label: string; values: string[] }> = []
      if (policy.config.max_cvss !== undefined) {
        fields.push({ label: 'Max CVSS', values: [String(policy.config.max_cvss)] })
      }
      if (policy.config.minimum_severity !== undefined) {
        fields.push({ label: 'Minimum severity', values: [formatSeverityLabel(policy.config.minimum_severity)] })
      }
      return fields
    }
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
        values: [
          (policy.config.unavailable_scorecard_behavior ?? 'deny') === 'skip' ? 'Skip this policy' : 'Deny artifact',
        ],
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
    primaryField.values.length <= 1 ? (primaryField.values[0] ?? 'No value') : summarizeListValues(primaryField.values)

  return {
    label: primaryField.label,
    value: extraFields.length > 0 ? `${primaryValue} • +${extraFields.length} more` : primaryValue,
  }
}

export function getPolicyBehaviorSummary(policy: PolicyDisplayRecord): string {
  const verb = actionVerb(policy)

  switch (policy.type) {
    case 'cvss_threshold': {
      const thresholds = [
        policy.config.max_cvss === undefined ? null : `CVSS is ${policy.config.max_cvss} or higher`,
        policy.config.minimum_severity === undefined
          ? null
          : `severity is ${formatSeverityLabel(policy.config.minimum_severity)} or higher`,
      ].filter((value): value is string => Boolean(value))
      return `${verb} packages when ${thresholds.join(' or ') || 'the vulnerability threshold matches'}.`
    }
    case 'minimum_age':
      return `${verb} packages published less than ${policy.config.min_age_days} days ago${policy.config.exclude_packages?.length ? `, except ${summarizeRuleValues(policy.config.exclude_packages)}` : ''}.`
    case 'maximum_age':
      return `${verb} packages published more than ${policy.config.max_age_days} days ago${policy.config.exclude_packages?.length ? `, except ${summarizeRuleValues(policy.config.exclude_packages)}` : ''}.`
    case 'block_mutable_tag':
      return `${verb} OCI images using mutable tags: ${summarizeRuleValues(policy.config.tags)}.`
    case 'scorecard': {
      const thresholds = [
        policy.config.min_score === undefined ? null : `overall score is below ${policy.config.min_score}`,
        policy.config.checks && Object.keys(policy.config.checks).length > 0
          ? 'a named check is below its minimum'
          : null,
      ].filter((value): value is string => Boolean(value))
      return `${verb} packages when ${thresholds.join(' or ') || 'the OpenSSF Scorecard rule matches'}.`
    }
    case 'license':
      return `${verb} packages declaring ${summarizeRuleValues(policy.config.licenses)}.`
    case 'license_allowlist':
      return `${verb} packages unless every declared license is approved: ${summarizeRuleValues(policy.config.licenses)}.`
    case 'allowlist':
      return `${verb} trusted namespaces: ${summarizeRuleValues(policy.config.namespaces)}. Later deny rules can still block them.`
    case 'namespace_allowlist':
      return `${verb} packages outside approved namespaces: ${summarizeRuleValues(policy.config.namespaces)}.`
    case 'blocklist':
      return `${verb} packages from blocked namespaces: ${summarizeRuleValues(policy.config.namespaces)}.`
  }
}

export function formatPolicyActionLabel(action: string): string {
  return action === 'allow' ? 'Allow' : action === 'deny' ? 'Deny' : action
}

export function getPolicyTargetSummary(policy: PolicyDisplayRecord): string {
  const target = policy.target
  if (!target) {
    return 'All dependencies'
  }

  const scopeLabels = (target.dependency_scope ?? []).map((scope) =>
    scope === 'direct' ? 'Direct' : scope === 'transitive' ? 'Transitive' : 'Unknown scope',
  )
  const typeLabels = (target.dependency_types ?? []).map((type) =>
    type === 'prod' ? 'Production' : type === 'dev' ? 'Development' : type === 'peer' ? 'Peer' : 'Optional',
  )
  const parts: string[] = [
    scopeLabels.length > 0 ? scopeLabels.join(' + ') : null,
    typeLabels.length > 0 ? typeLabels.join(' + ') : null,
  ].filter((value): value is string => Boolean(value))
  if (parts.length === 0) {
    parts.push('All dependencies')
  }
  if (target.on_unknown) {
    parts.push(
      `Unknown graph: ${target.on_unknown === 'warn' ? 'Warn only' : target.on_unknown === 'deny' ? 'Evaluate normally' : 'Skip'}`,
    )
  }

  return parts.join(' • ')
}

export function matchesPolicySearch(policy: TypedPolicy, upstreamsByID: Map<string, Upstream>, query: string) {
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
