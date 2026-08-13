import { useMemo, useState } from 'react'
import { SearchFilterBar } from '../components/filters/SearchFilterBar.tsx'
import { EvaluationList, QueryStateNotice, SummaryMetrics } from '../features/evaluations/components.tsx'
import { evaluationsPageSize, useEvaluationsPage } from '../features/evaluations/api.ts'
import {
  evaluationFilterOptions,
  matchesEvaluationFilter,
  matchesEvaluationFilters,
  toggleEvaluationFilter,
  type EvaluationFilter,
} from '../features/evaluations/filters.ts'
import { formatTimestamp, getQueryErrorMessage, summarizeEvaluations } from '../features/evaluations/model.ts'
import { evaluationClass } from '../features/evaluations/styles.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { PageHeader } from '../ui/index.ts'

export function EvaluationsPage() {
  const { activeTenant, tenantId } = useTenant()
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
      return {
        ...currentPages,
        [tenantKey]: typeof nextPage === 'function' ? nextPage(currentPage) : nextPage,
      }
    })
  }

  const offset = page * evaluationsPageSize
  const evaluationsQuery = useEvaluationsPage(evaluationsPageSize, offset, artifactSearch)
  const evaluations = useMemo(() => evaluationsQuery.data ?? [], [evaluationsQuery.data])
  const visibleEvaluations = useMemo(
    () => evaluations.filter((evaluation) => matchesEvaluationFilters(evaluation, activeFilters)),
    [activeFilters, evaluations],
  )
  const evaluationSummary = summarizeEvaluations(evaluations)
  const rangeStart = offset + 1
  const rangeEnd = offset + evaluations.length
  const canGoBack = page > 0
  const canGoForward = evaluations.length === evaluationsPageSize
  const hasArtifactSearch = artifactSearch.trim().length > 0
  const hasActiveFilters = activeFilters.length > 0
  const emptyTitle = hasArtifactSearch || hasActiveFilters
    ? 'No matching decisions'
    : page === 0
      ? 'No decisions recorded yet'
      : 'No more decisions'
  const emptyMessage = hasArtifactSearch || hasActiveFilters
    ? 'Adjust the search or clear a filter to see more decision history.'
    : page === 0
      ? 'Decisions appear here after this tenant routes package or image requests through Dependency Firewall.'
      : 'Return to the previous page or refresh to look for newer decisions.'
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
    () => evaluationFilterOptions.map((option) => ({ ...option, count: filterCounts[option.id] })),
    [filterCounts],
  )

  const summaryMetrics = [
    {
      label: 'Loaded decisions',
      value: String(evaluationSummary.total),
      hint: `Page ${page + 1}`,
    },
    { label: 'Allowed', value: String(evaluationSummary.allowCount), hint: 'Loaded page', tone: 'success' },
    { label: 'Denied', value: String(evaluationSummary.denyCount), hint: 'Loaded page', tone: 'danger' },
    { label: 'Dry-run warnings', value: String(evaluationSummary.warningCount), hint: 'Loaded page', tone: 'warning' },
  ] as const

  return (
    <section className={evaluationClass('page')}>
      <PageHeader
        eyebrow="Decision history"
        title="Evaluations"
        summary={<>See what Dependency Firewall decided for {activeTenant?.name ?? 'the selected tenant'}, which policy made the decision, and why.</>}
        actions={<>
          {evaluationsQuery.isFetching && !evaluationsQuery.isPending ? (
            <span className={evaluationClass('status-pill status-pill-neutral')}>Refreshing</span>
          ) : null}
          {!evaluationsQuery.isError ? (
            <button
              className={evaluationClass('secondary-button')}
              disabled={evaluationsQuery.isFetching}
              onClick={() => void evaluationsQuery.refetch()}
              type="button"
            >
              Refresh
            </button>
          ) : null}
        </>}
      />

      {evaluationsQuery.isSuccess && evaluations.length > 0 ? (
        <section className={evaluationClass('evaluations-overview')} aria-labelledby="evaluation-overview-title">
          <div className={evaluationClass('section-header')}>
            <div>
              <h3 id="evaluation-overview-title">Decision overview</h3>
              <p className={evaluationClass('muted')}>
                Results {rangeStart}-{rangeEnd} · latest {formatTimestamp(evaluationSummary.latestEvaluatedAt)} ·{' '}
                {evaluationSummary.uniquePolicies} {evaluationSummary.uniquePolicies === 1 ? 'policy' : 'policies'} represented ·{' '}
                {evaluationSummary.cachedCount} cached
              </p>
            </div>
            <span className={evaluationClass('status-pill status-pill-neutral')}>Page {page + 1}</span>
          </div>
          <SummaryMetrics items={summaryMetrics} />
        </section>
      ) : null}

      <section className={evaluationClass('card evaluations-log-card')}>
        <div className={evaluationClass('section-header')}>
          <div>
            <h3>Decision history</h3>
            {evaluations.length > 0 ? (
              <p className={evaluationClass('muted')}>
                {visibleEvaluations.length === evaluations.length
                  ? `${evaluations.length} decisions loaded on this page.`
                  : `${visibleEvaluations.length} of ${evaluations.length} loaded decisions match.`}
              </p>
            ) : null}
          </div>
          {evaluations.length > 0 ? (
            <div className={evaluationClass('button-row evaluations-pagination')} aria-label="Evaluation pages">
              <button
                className={evaluationClass('secondary-button')}
                disabled={!canGoBack || evaluationsQuery.isFetching}
                onClick={() => updatePage((currentPage) => Math.max(currentPage - 1, 0))}
                type="button"
              >
                Previous
              </button>
              <button
                className={evaluationClass('secondary-button')}
                disabled={!canGoForward || evaluationsQuery.isFetching}
                onClick={() => updatePage((currentPage) => currentPage + 1)}
                type="button"
              >
                Next
              </button>
            </div>
          ) : null}
        </div>

        {evaluations.length > 0 || hasArtifactSearch || hasActiveFilters ? (
          <SearchFilterBar
            activeFilters={activeFilters}
            clearFiltersLabel="Clear filters"
            filterGroupLabel="Evaluation filters"
            filterOptions={evaluationFilters}
            onClearFilters={() => setActiveFiltersByTenant((current) => ({ ...current, [tenantKey]: [] }))}
            onSearchChange={(nextSearch) => {
              updatePage(0)
              setArtifactSearchByTenant((current) => ({ ...current, [tenantKey]: nextSearch }))
            }}
            onToggleFilter={(filter) =>
              setActiveFiltersByTenant((current) => ({
                ...current,
                [tenantKey]: toggleEvaluationFilter(current[tenantKey] ?? [], filter),
              }))
            }
            searchFieldClassName="evaluation-search"
            searchHelpText="Search package or image name, version, scope, or digest."
            searchInputId="evaluation-artifact-search"
            searchLabel="Artifact search"
            searchPlaceholder="lodash, @scope/pkg, 4.17.20, sha256:..."
            searchValue={artifactSearch}
          />
        ) : null}

        {evaluationsQuery.isPending ? (
          <QueryStateNotice title="Loading decision history" message="Waiting for stored evaluations." />
        ) : evaluationsQuery.isError ? (
          <QueryStateNotice
            title="Unable to load decision history"
            message={getQueryErrorMessage(evaluationsQuery.error, 'Decision history is unavailable right now.')}
            onAction={() => void evaluationsQuery.refetch()}
          />
        ) : (
          <EvaluationList emptyMessage={emptyMessage} emptyTitle={emptyTitle} evaluations={visibleEvaluations} />
        )}
      </section>
    </section>
  )
}
