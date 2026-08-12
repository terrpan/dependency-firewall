// Evaluation filter helpers keep audit-log filtering rules out of the page component.
import type { Evaluation } from '../../lib/api/index.ts'

export type EvaluationFilter = 'allow' | 'deny' | 'dry_run' | 'cached'

export const evaluationFilterOptions = [
  { id: 'allow', label: 'Allow', tone: 'success' },
  { id: 'deny', label: 'Deny', tone: 'danger' },
  { id: 'dry_run', label: 'Dry run', tone: 'warning' },
  { id: 'cached', label: 'Cached', tone: 'info' },
] as const

const outcomeFilters = new Set<EvaluationFilter>(['allow', 'deny'])

export function matchesEvaluationFilter(evaluation: Evaluation, filter: EvaluationFilter) {
  if (filter === 'allow') {
    return evaluation.outcome.toLowerCase() === 'allow'
  }

  if (filter === 'deny') {
    return evaluation.outcome.toLowerCase() === 'deny'
  }

  if (filter === 'dry_run') {
    return (evaluation.warnings?.length ?? 0) > 0
  }

  return Boolean(evaluation.cached_at)
}

export function matchesEvaluationFilters(
  evaluation: Evaluation,
  filters: readonly EvaluationFilter[],
): boolean {
  return filters.every((filter) => matchesEvaluationFilter(evaluation, filter))
}

export function toggleEvaluationFilter(
  filters: readonly EvaluationFilter[],
  filter: EvaluationFilter,
): EvaluationFilter[] {
  if (filters.includes(filter)) {
    return filters.filter((currentFilter) => currentFilter !== filter)
  }

  const withoutOtherOutcome = outcomeFilters.has(filter)
    ? filters.filter((currentFilter) => !outcomeFilters.has(currentFilter))
    : filters

  return [...withoutOtherOutcome, filter]
}
