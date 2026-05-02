import { useMemo, useState } from 'react'
import {
  SearchFilterBar,
  type FilterChipOption,
} from '../components/filters/SearchFilterBar.tsx'
import type { Evaluation } from '../lib/api/index.ts'
import {
  EvaluationList,
  QueryStateNotice,
  SummaryMetrics,
} from '../features/evaluations/components.tsx'
import { evaluationsPageSize, useEvaluationsPage } from '../features/evaluations/api.ts'
import {
  formatTimestamp,
  getQueryErrorMessage,
  summarizeEvaluations,
} from '../features/evaluations/model.ts'
import { useTenant } from '../features/tenant/useTenant.ts'

type EvaluationFilter = 'allow' | 'deny' | 'dry_run' | 'cached'

const evaluationFilterOptions = [
  { id: 'allow', label: 'Allow', tone: 'success' },
  { id: 'deny', label: 'Deny', tone: 'danger' },
  { id: 'dry_run', label: 'Dry run', tone: 'warning' },
  { id: 'cached', label: 'Cached', tone: 'info' },
] satisfies readonly FilterChipOption<EvaluationFilter>[]

function matchesEvaluationFilter(evaluation: Evaluation, filter: EvaluationFilter) {
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

export function EvaluationsPage() {
  const { tenantId } = useTenant()
  const tenantKey = tenantId ?? 'tenant-pending'
  const [pagesByTenant, setPagesByTenant] = useState<Record<string, number>>({})
  const [artifactSearchByTenant, setArtifactSearchByTenant] = useState<Record<string, string>>({})
  const [activeFiltersByTenant, setActiveFiltersByTenant] = useState<Record<string, EvaluationFilter[]>>({})
  const page = pagesByTenant[tenantKey] ?? 0
  const artifactSearch = artifactSearchByTenant[tenantKey] ?? ''
  const activeFilters = useMemo(
    () => activeFiltersByTenant[tenantKey] ?? [],
    [activeFiltersByTenant, tenantKey],
  )

  function updatePage(nextPage: number | ((currentPage: number) => number)) {
    setPagesByTenant((currentPages) => {
      const currentPage = currentPages[tenantKey] ?? 0
      const resolvedNextPage =
        typeof nextPage === 'function' ? nextPage(currentPage) : nextPage

      return {
        ...currentPages,
        [tenantKey]: resolvedNextPage,
      }
    })
  }

  const offset = page * evaluationsPageSize
  const evaluationsQuery = useEvaluationsPage(evaluationsPageSize, offset, artifactSearch)
  const evaluations = useMemo(() => evaluationsQuery.data ?? [], [evaluationsQuery.data])
  const visibleEvaluations = useMemo(() => {
    if (activeFilters.length === 0) {
      return evaluations
    }

    return evaluations.filter((evaluation) =>
      activeFilters.some((filter) => matchesEvaluationFilter(evaluation, filter)),
    )
  }, [activeFilters, evaluations])
  const evaluationSummary = summarizeEvaluations(visibleEvaluations)
  const rangeStart = offset + 1
  const rangeEnd = offset + evaluations.length
  const canGoBack = page > 0
  const canGoForward = evaluations.length === evaluationsPageSize
  const hasArtifactSearch = artifactSearch.trim().length > 0
  const hasActiveFilters = activeFilters.length > 0
  const emptyTitle = hasArtifactSearch || hasActiveFilters
    ? 'No matching evaluations'
    : page === 0
      ? 'No evaluations recorded'
      : 'No more evaluations on this page'
  const emptyMessage = hasArtifactSearch || hasActiveFilters
    ? 'Try a different artifact search or filter combination.'
    : page === 0
      ? 'This tenant does not have any stored evaluation history yet.'
      : 'Try the previous page or refresh to look for newer results.'
  const filterCounts = useMemo(
    () => ({
      allow: evaluations.filter((evaluation) => matchesEvaluationFilter(evaluation, 'allow')).length,
      deny: evaluations.filter((evaluation) => matchesEvaluationFilter(evaluation, 'deny')).length,
      dry_run: evaluations.filter((evaluation) => matchesEvaluationFilter(evaluation, 'dry_run')).length,
      cached: evaluations.filter((evaluation) => matchesEvaluationFilter(evaluation, 'cached')).length,
    }),
    [evaluations],
  )
  const evaluationFilters = useMemo(
    () =>
      evaluationFilterOptions.map((option) => ({
        ...option,
        count: filterCounts[option.id],
      })),
    [filterCounts],
  )

  const summaryMetrics = [
    {
      label: 'Results shown',
      value: String(evaluationSummary.total),
      hint:
        hasArtifactSearch || hasActiveFilters
          ? `Filtered from ${evaluations.length} loaded results on page ${page + 1}`
          : `Current page size ${evaluationsPageSize}`,
    },
    {
      label: 'Allowed',
      value: String(evaluationSummary.allowCount),
      hint: 'Current page only',
      tone: 'success',
    },
    {
      label: 'Denied',
      value: String(evaluationSummary.denyCount),
      hint: 'Current page only',
      tone: 'danger',
    },
    {
      label: 'With warnings',
      value: String(evaluationSummary.warningCount),
      hint: 'Current page only',
    },
  ] as const

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Decision history</p>
          <h2>Evaluations</h2>
          <p className="page-summary">
            Review recent allow and deny outcomes, page through stored decisions, and inspect audit
            detail without leaving the log.
          </p>
        </div>

        <div className="page-actions">
          {evaluationsQuery.isFetching && !evaluationsQuery.isPending ? (
            <span className="status-pill">Refreshing</span>
          ) : null}
          <button
            className="secondary-button"
            onClick={() => void evaluationsQuery.refetch()}
            type="button"
          >
            Refresh
          </button>
        </div>
      </header>

      <div className="evaluations-layout">
        <div className="evaluations-side-stack">
          <section className="card">
            <div className="section-header">
              <div>
                <h3>Current page summary</h3>
                <p className="muted">
                  {evaluations.length > 0
                    ? `Showing results ${rangeStart}-${rangeEnd}${hasArtifactSearch || hasActiveFilters ? ' for the current search and filters.' : '.'}`
                    : `Showing page ${page + 1}.`}
                </p>
              </div>
              <span className="status-pill status-pill-neutral">Page {page + 1}</span>
            </div>

            <div className="button-row">
              <button
                className="secondary-button"
                disabled={!canGoBack || evaluationsQuery.isPending}
                onClick={() => updatePage((currentPage) => Math.max(currentPage - 1, 0))}
                type="button"
              >
                Previous
              </button>
              <button
                className="secondary-button"
                disabled={!canGoForward || evaluationsQuery.isPending}
                onClick={() => updatePage((currentPage) => currentPage + 1)}
                type="button"
              >
                Next
              </button>
            </div>

            {evaluationsQuery.isPending ? (
              <QueryStateNotice
                title="Loading evaluation summary"
                message="Waiting for decision history."
              />
            ) : evaluationsQuery.isError ? (
              <QueryStateNotice
                title="Unable to load evaluation summary"
                message={getQueryErrorMessage(
                  evaluationsQuery.error,
                  'Evaluation summary data is unavailable right now.',
                )}
                onAction={() => void evaluationsQuery.refetch()}
              />
            ) : evaluations.length === 0 ? (
              <QueryStateNotice title={emptyTitle} message={emptyMessage} />
            ) : (
              <>
                <SummaryMetrics items={summaryMetrics} />
                <p className="muted">
                  Latest result on this page: {formatTimestamp(evaluationSummary.latestEvaluatedAt)}
                  . Policies represented: {evaluationSummary.uniquePolicies}. Cached results:{' '}
                  {evaluationSummary.cachedCount}.
                </p>
              </>
            )}
          </section>

          <section className="card">
            <h3>Audit view notes</h3>
            <ul className="list">
              <li>Outcome summary is derived from the currently loaded page only.</li>
              <li>Reasons come from recorded evaluation audit data; no backend fields are invented.</li>
              <li>Policy hash and cache timestamps stay visible for operator debugging.</li>
            </ul>
          </section>
        </div>

        <section className="card evaluations-log-card">
          <div className="section-header">
            <div>
              <h3>Audit log</h3>
              <p className="muted">
                Stored decisions, primary reasons, warnings, and policy metadata for the selected
                tenant.
              </p>
            </div>
          </div>

          <SearchFilterBar
            activeFilters={activeFilters}
            clearFiltersLabel="Clear filters"
            filterGroupLabel="Evaluation filters"
            filterOptions={evaluationFilters}
            onClearFilters={() => setActiveFiltersByTenant((current) => ({ ...current, [tenantKey]: [] }))}
            onSearchChange={(nextSearch) => {
              updatePage(0)
              setArtifactSearchByTenant((currentSearches) => ({
                ...currentSearches,
                [tenantKey]: nextSearch,
              }))
            }}
            onToggleFilter={(filter) =>
              setActiveFiltersByTenant((current) => {
                const currentFilters = current[tenantKey] ?? []

                return {
                  ...current,
                  [tenantKey]: currentFilters.includes(filter)
                    ? currentFilters.filter((currentFilter) => currentFilter !== filter)
                    : [...currentFilters, filter],
                }
              })
            }
            searchFieldClassName="evaluation-search"
            searchHelpText="Searches stored evaluations for this tenant by artifact name, scope, version, or digest."
            searchInputId="evaluation-artifact-search"
            searchLabel="Artifact search"
            searchPlaceholder="lodash, @scope/pkg, 4.17.20, sha256:..."
            searchValue={artifactSearch}
          />

          {evaluationsQuery.isPending ? (
            <QueryStateNotice
              title="Loading evaluations"
              message="Waiting for the audit log to load."
            />
          ) : evaluationsQuery.isError ? (
            <QueryStateNotice
              title="Unable to load evaluations"
              message={getQueryErrorMessage(
                evaluationsQuery.error,
                'Evaluation history is unavailable right now.',
              )}
              onAction={() => void evaluationsQuery.refetch()}
            />
          ) : (
            <EvaluationList
              emptyMessage={emptyMessage}
              emptyTitle={emptyTitle}
              evaluations={visibleEvaluations}
            />
          )}
        </section>
      </div>
    </section>
  )
}
