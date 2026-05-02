import type { Evaluation, Health } from '../../lib/api/index.ts'

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

export type Tone = 'default' | 'success' | 'danger' | 'warning'

export type EvaluationSummary = {
  total: number
  allowCount: number
  denyCount: number
  warningCount: number
  cachedCount: number
  latestEvaluatedAt: string | null
  uniquePolicies: number
}

type EvaluationReason = NonNullable<Evaluation['reasons']>[number]

function parseDate(value?: string | null): Date | null {
  if (!value) {
    return null
  }

  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

export function formatTimestamp(value?: string | null): string {
  const date = parseDate(value)
  return date ? dateTimeFormatter.format(date) : '—'
}

export function formatRelativeTime(value?: string | null): string {
  const date = parseDate(value)
  if (!date) {
    return 'unknown time'
  }

  const deltaMs = Date.now() - date.getTime()
  const deltaSeconds = Math.round(deltaMs / 1000)

  if (Math.abs(deltaSeconds) < 60) {
    return 'just now'
  }

  const deltaMinutes = Math.round(deltaSeconds / 60)
  if (Math.abs(deltaMinutes) < 60) {
    return deltaMinutes > 0 ? `${deltaMinutes}m ago` : `in ${Math.abs(deltaMinutes)}m`
  }

  const deltaHours = Math.round(deltaMinutes / 60)
  if (Math.abs(deltaHours) < 24) {
    return deltaHours > 0 ? `${deltaHours}h ago` : `in ${Math.abs(deltaHours)}h`
  }

  const deltaDays = Math.round(deltaHours / 24)
  return deltaDays > 0 ? `${deltaDays}d ago` : `in ${Math.abs(deltaDays)}d`
}

export function formatDuration(durationMs: number): string {
  if (durationMs < 1_000) {
    return `${durationMs} ms`
  }

  if (durationMs < 60_000) {
    const seconds = durationMs / 1_000
    return `${seconds.toFixed(seconds >= 10 ? 0 : 1)} s`
  }

  return `${(durationMs / 60_000).toFixed(1)} min`
}

export function shortenHash(value?: string | null, maxLength = 12): string {
  if (!value) {
    return '—'
  }

  if (value.length <= maxLength) {
    return value
  }

  return `${value.slice(0, maxLength)}…`
}

function nonEmpty(value?: string | null): string | null {
  const trimmed = value?.trim()
  return trimmed ? trimmed : null
}

export function formatArtifact(artifact: Evaluation['artifact']): string {
  const qualifiedName = artifact.namespace ? `${artifact.namespace}/${artifact.name}` : artifact.name

  if (artifact.version) {
    return `${qualifiedName}@${artifact.version}`
  }

  if (artifact.digest) {
    return `${qualifiedName}@${shortenHash(artifact.digest, 18)}`
  }

  return qualifiedName
}

export function formatPolicyReference(evaluation: Evaluation): string {
  const primaryReason = evaluation.reasons?.find(
    (reason) => nonEmpty(reason.policy_name) || nonEmpty(reason.policy_id),
  )

  return (
    nonEmpty(primaryReason?.policy_name) ??
    nonEmpty(primaryReason?.policy_id) ??
    nonEmpty(evaluation.policy_id) ??
    'No matched policy recorded'
  )
}

export function formatPolicyId(evaluation: Evaluation): string {
  const primaryReason = evaluation.reasons?.find((reason) => nonEmpty(reason.policy_id))
  return nonEmpty(evaluation.policy_id) ?? nonEmpty(primaryReason?.policy_id) ?? 'Not recorded'
}

export function formatReasonPolicyLabel(reason: EvaluationReason): string {
  return nonEmpty(reason.policy_name) ?? nonEmpty(reason.policy_id) ?? 'Policy rule'
}

export function formatNamespace(artifact: Evaluation['artifact']): string {
  const namespace = nonEmpty(artifact.namespace)
  if (namespace) {
    return namespace
  }

  return artifact.ecosystem.toLowerCase() === 'npm' ? 'Unscoped package' : 'No namespace recorded'
}

export function formatCachedAt(value?: string | null): string {
  return nonEmpty(value) ? formatTimestamp(value) : 'Not cached'
}

export function hasDryRunWarning(evaluation: Evaluation): boolean {
  return (evaluation.warnings?.length ?? 0) > 0
}

export function getPrimaryReason(evaluation: Evaluation): string {
  if (evaluation.reason.trim()) {
    return evaluation.reason
  }

  const firstMatchedReason = evaluation.reasons?.find((reason) => reason.message.trim())
  return firstMatchedReason?.message ?? 'No evaluation reason recorded.'
}

function normalizeStatus(value: string): string {
  return value.trim().toLowerCase()
}

export function getOutcomeTone(outcome: string): Tone {
  return normalizeStatus(outcome) === 'deny'
    ? 'danger'
    : normalizeStatus(outcome) === 'allow'
      ? 'success'
      : 'default'
}

export function getStatusTone(status: string): Tone {
  const normalizedStatus = normalizeStatus(status)

  if (
    normalizedStatus.includes('down') ||
    normalizedStatus.includes('error') ||
    normalizedStatus.includes('fail') ||
    normalizedStatus.includes('unhealthy') ||
    normalizedStatus.includes('degraded')
  ) {
    return 'danger'
  }

  if (
    normalizedStatus.includes('ok') ||
    normalizedStatus.includes('up') ||
    normalizedStatus.includes('ready') ||
    normalizedStatus.includes('healthy')
  ) {
    return 'success'
  }

  return 'default'
}

export function summarizeEvaluations(evaluations: readonly Evaluation[]): EvaluationSummary {
  const summary: EvaluationSummary = {
    total: evaluations.length,
    allowCount: 0,
    denyCount: 0,
    warningCount: 0,
    cachedCount: 0,
    latestEvaluatedAt: null,
    uniquePolicies: 0,
  }

  const policyIds = new Set<string>()

  for (const evaluation of evaluations) {
    const normalizedOutcome = normalizeStatus(evaluation.outcome)

    if (normalizedOutcome === 'allow') {
      summary.allowCount += 1
    } else if (normalizedOutcome === 'deny') {
      summary.denyCount += 1
    }

    if ((evaluation.warnings?.length ?? 0) > 0) {
      summary.warningCount += 1
    }

    if (evaluation.cached_at) {
      summary.cachedCount += 1
    }

    if (evaluation.policy_id) {
      policyIds.add(evaluation.policy_id)
    }

    const latestDate = parseDate(summary.latestEvaluatedAt)
    const currentDate = parseDate(evaluation.evaluated_at)
    if (!currentDate) {
      continue
    }

    if (!latestDate || currentDate > latestDate) {
      summary.latestEvaluatedAt = evaluation.evaluated_at
    }
  }

  summary.uniquePolicies = policyIds.size
  return summary
}

export function summarizeDependencies(health: Health | undefined) {
  const dependencies = Object.entries(health?.dependencies ?? {})
  const degradedCount = dependencies.filter(([, dependency]) => getStatusTone(dependency.status) === 'danger').length

  return {
    dependencies,
    degradedCount,
    total: dependencies.length,
  }
}

export function getQueryErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error) {
    const message = error.message.trim()
    return message || fallback
  }

  return fallback
}
