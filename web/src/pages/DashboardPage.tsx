import { Link } from 'react-router-dom'
import {
  ControlPlaneHealthCard,
  EvaluationList,
  QueryStateNotice,
  SummaryMetrics,
} from '../features/evaluations/components.tsx'
import { dashboardEvaluationsLimit, useHealth, useRecentEvaluations } from '../features/evaluations/api.ts'
import {
  formatRelativeTime,
  getQueryErrorMessage,
  getStatusTone,
  summarizeEvaluations,
} from '../features/evaluations/model.ts'

type RouteCard = {
  title: string
  path: string
  description: string
}

const routeCards = [
  {
    title: 'Tenants',
    path: '/tenants',
    description: 'Tenant discovery and setup.',
  },
  {
    title: 'Upstreams',
    path: '/upstreams',
    description: 'Registry endpoints and connectivity.',
  },
  {
    title: 'Policies',
    path: '/policies',
    description: 'Rules, versions, and rollback.',
  },
  {
    title: 'Evaluations',
    path: '/evaluations',
    description: 'Audit history and recent decisions.',
  },
] satisfies readonly RouteCard[]

export function DashboardPage() {
  const healthQuery = useHealth()
  const recentEvaluationsQuery = useRecentEvaluations(dashboardEvaluationsLimit)
  const recentEvaluations = recentEvaluationsQuery.data ?? []
  const evaluationSummary = summarizeEvaluations(recentEvaluations)
  const headerStatusTone = healthQuery.data ? getStatusTone(healthQuery.data.status) : undefined

  const headerStatusLabel = healthQuery.isPending
    ? 'Loading status'
    : healthQuery.isError || !healthQuery.data
      ? 'Status unavailable'
      : healthQuery.data.status.toUpperCase()

  const headerStatusClassName =
    headerStatusTone === 'success'
      ? 'status-pill status-pill-success'
      : headerStatusTone === 'danger'
        ? 'status-pill status-pill-danger'
        : 'status-pill'

  const summaryMetrics = [
    {
      label: 'Recent decisions',
      value: String(evaluationSummary.total),
      hint: `Latest ${dashboardEvaluationsLimit} results`,
    },
    {
      label: 'Allowed',
      value: String(evaluationSummary.allowCount),
      hint: 'In the current window',
      tone: 'success',
    },
    {
      label: 'Denied',
      value: String(evaluationSummary.denyCount),
      hint: 'In the current window',
      tone: 'danger',
    },
    {
      label: 'With warnings',
      value: String(evaluationSummary.warningCount),
      hint: 'Results with warning tags',
    },
  ] as const

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Overview</p>
          <h2>Dashboard</h2>
          <p className="page-summary">Recent decisions, service health, and the quickest way into the next task.</p>
        </div>
        <div className="page-actions">
          <span className={headerStatusClassName}>{headerStatusLabel}</span>
          <Link className="route-link" to="/evaluations">
            View evaluations
          </Link>
        </div>
      </header>

      <div className="dashboard-hero">
        <section className="card dashboard-primary-card">
          <div className="section-header">
            <div>
              <h3>Recent activity</h3>
              <p className="muted">A compact read on the latest decision outcomes.</p>
            </div>
            {recentEvaluationsQuery.isFetching && !recentEvaluationsQuery.isPending ? (
              <span className="status-pill">Refreshing</span>
            ) : null}
          </div>

          {recentEvaluationsQuery.isPending ? (
            <QueryStateNotice
              title="Loading recent evaluations"
              message="Waiting for recent decision history."
            />
          ) : recentEvaluationsQuery.isError ? (
            <QueryStateNotice
              title="Unable to load recent evaluations"
              message={getQueryErrorMessage(
                recentEvaluationsQuery.error,
                'Recent evaluation data is unavailable right now.',
              )}
              onAction={() => void recentEvaluationsQuery.refetch()}
            />
          ) : recentEvaluations.length === 0 ? (
            <QueryStateNotice
              title="No evaluations recorded"
              message="This tenant does not have any stored evaluation history yet."
            />
          ) : (
            <>
              <SummaryMetrics items={summaryMetrics} />
              <div className="dashboard-card-actions">
                <p className="muted">
                  Latest evaluation {formatRelativeTime(evaluationSummary.latestEvaluatedAt)}. Cached
                  results: {evaluationSummary.cachedCount}. Policies represented:{' '}
                  {evaluationSummary.uniquePolicies}.
                </p>
                <Link className="route-link" to="/evaluations">
                  Open audit trail
                </Link>
              </div>
            </>
          )}
        </section>

        <ControlPlaneHealthCard
          error={healthQuery.error}
          health={healthQuery.data}
          isLoading={healthQuery.isPending}
          onRetry={() => void healthQuery.refetch()}
        />
      </div>

      <div className="dashboard-lower-grid">
        <section className="card dashboard-span-wide">
          <div className="section-header">
            <div>
              <h3>Recent evaluations</h3>
              <p className="muted">Latest decisions and primary reasons.</p>
            </div>
          </div>

          {recentEvaluationsQuery.isPending ? (
            <QueryStateNotice
              title="Loading evaluation preview"
              message="The dashboard is waiting for recent decision history."
            />
          ) : recentEvaluationsQuery.isError ? (
            <QueryStateNotice
              title="Unable to load evaluation preview"
              message={getQueryErrorMessage(
                recentEvaluationsQuery.error,
                'Evaluation preview data is unavailable right now.',
              )}
              onAction={() => void recentEvaluationsQuery.refetch()}
            />
          ) : (
            <EvaluationList
              compact
              emptyMessage="This tenant does not have any stored evaluation history yet."
              evaluations={recentEvaluations.slice(0, 5)}
            />
          )}
        </section>

        <section className="card">
          <div className="section-header">
            <div>
              <h3>Quick links</h3>
              <p className="muted">Jump straight to the main control-plane surfaces.</p>
            </div>
            <Link className="route-link" to="/upstreams">
              Open upstreams
            </Link>
          </div>
          <ul className="route-list dashboard-route-grid">
            {routeCards.map((route) => (
              <li key={route.path} className="route-card">
                <p className="route-label">{route.path}</p>
                <h3>{route.title}</h3>
                <p className="muted">{route.description}</p>
                <Link className="route-link" to={route.path}>
                  Open
                </Link>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </section>
  )
}
