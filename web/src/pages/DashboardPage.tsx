import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  ControlPlaneHealthCard,
  QueryStateNotice,
  SummaryMetrics,
} from '../features/evaluations/components.tsx'
import { dashboardEvaluationsLimit, useHealth, useRecentEvaluations } from '../features/evaluations/api.ts'
import {
  formatArtifact,
  formatRelativeTime,
  formatPolicyReference,
  getOutcomeTone,
  getPrimaryReason,
  getQueryErrorMessage,
  getStatusTone,
  summarizeEvaluations,
} from '../features/evaluations/model.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { useTenantControlPlaneApi } from '../features/tenant/useTenantControlPlaneApi.ts'
import {
  listUpstreams,
  sortUpstreams,
  upstreamsQueryKey,
} from '../features/upstreams/api.ts'
import { asTypedPolicy, type Evaluation, type Health, type TypedPolicy, type Upstream } from '../lib/api/index.ts'
import { sortPolicies } from '../features/policies/display.ts'
import { evaluationClass } from '../features/evaluations/styles.ts'

type AttentionItem = {
  key: string
  title: string
  detail: string
  tone?: 'danger' | 'warning' | 'success'
  to?: string
  actionLabel?: string
}

type Segment = {
  label: string
  value: number
  tone?: 'success' | 'danger' | 'warning' | 'default'
}

function statusPillClassName(tone: 'default' | 'success' | 'danger' | 'warning' | undefined) {
  return evaluationClass(
    'status-pill',
    tone === 'success' && 'status-pill-success',
    tone === 'danger' && 'status-pill-danger',
    tone === 'warning' && 'status-pill-warning',
  )
}

function segmentClassName(tone: Segment['tone']) {
  if (tone === 'success') {
    return evaluationClass('dashboard-bar-segment', 'dashboard-bar-segment-success')
  }

  if (tone === 'danger') {
    return evaluationClass('dashboard-bar-segment', 'dashboard-bar-segment-danger')
  }

  if (tone === 'warning') {
    return evaluationClass('dashboard-bar-segment', 'dashboard-bar-segment-warning')
  }

  return evaluationClass('dashboard-bar-segment')
}

function formatPercent(numerator: number, denominator: number) {
  if (denominator === 0) {
    return '0%'
  }

  return `${Math.round((numerator / denominator) * 100)}%`
}

function DashboardCompactBar({
  label,
  total,
  segments,
}: {
  label: string
  total: number
  segments: readonly Segment[]
}) {
  return (
    <div className={evaluationClass("dashboard-compact-bar")}>
      <div className={evaluationClass("dashboard-compact-bar-header")}>
        <span className={evaluationClass("metric-label")}>{label}</span>
        <span className={evaluationClass("muted")}>{total} total</span>
      </div>
      <div className={evaluationClass("dashboard-bar-track")} aria-label={label}>
        {segments.map((segment) => (
          <span
            key={segment.label}
            className={segmentClassName(segment.tone)}
            style={{ flexGrow: total > 0 ? segment.value : 0 }}
            title={`${segment.label}: ${segment.value} (${formatPercent(segment.value, total)})`}
          />
        ))}
        {total === 0 ? <span className={evaluationClass("dashboard-bar-empty")} /> : null}
      </div>
      <div className={evaluationClass("dashboard-bar-legend")}>
        {segments.map((segment) => (
          <span key={segment.label}>
            <span className={segmentClassName(segment.tone)} />
            {segment.label}: {segment.value}
          </span>
        ))}
      </div>
    </div>
  )
}

function getDependencyAttentionItems(health?: Health): AttentionItem[] {
  return Object.entries(health?.dependencies ?? {})
    .filter(([, dependency]) => getStatusTone(dependency.status) === 'danger')
    .map(([name, dependency]) => ({
      key: `dependency-${name}`,
      title: `${name} dependency degraded`,
      detail: dependency.message?.trim() || `Reported ${dependency.status}.`,
      tone: 'danger',
    }))
}

function buildAttentionItems(
  evaluations: readonly Evaluation[],
  health: Health | undefined,
  upstreams: readonly Upstream[],
  policies: readonly TypedPolicy[],
  tenantId: string | null,
  hasUpstreamsError: boolean,
  hasPoliciesError: boolean,
): AttentionItem[] {
  const items: AttentionItem[] = []

  items.push(...getDependencyAttentionItems(health))

  const deniedEvaluations = evaluations.filter((evaluation) => evaluation.outcome.toLowerCase() === 'deny')
  for (const evaluation of deniedEvaluations.slice(0, 3)) {
    items.push({
      key: `deny-${evaluation.id}`,
      title: `${formatArtifact(evaluation.artifact)} matched a deny policy`,
      detail: getPrimaryReason(evaluation),
      tone: 'warning',
      to: '/evaluations',
      actionLabel: 'Review',
    })
  }

  const warningEvaluation = evaluations.find((evaluation) => (evaluation.warnings?.length ?? 0) > 0)
  if (warningEvaluation) {
    items.push({
      key: `warning-${warningEvaluation.id}`,
      title: 'Decision warnings recorded',
      detail: `${formatArtifact(warningEvaluation.artifact)} has ${warningEvaluation.warnings?.length ?? 0} warning tag(s).`,
      tone: 'warning',
      to: '/evaluations',
      actionLabel: 'Review',
    })
  }

  if (!tenantId) {
    items.push({
      key: 'tenant-missing',
      title: 'No tenant selected',
      detail: 'Select or create a tenant before configuring upstreams and policies.',
      tone: 'warning',
      to: '/tenants',
      actionLabel: 'Choose tenant',
    })
  } else {
    if (hasUpstreamsError) {
      items.push({
        key: 'upstreams-error',
        title: 'Upstream inventory unavailable',
        detail: 'The dashboard could not load configured upstreams for this tenant.',
        tone: 'warning',
        to: '/upstreams',
        actionLabel: 'View upstreams',
      })
    } else if (upstreams.length === 0) {
      items.push({
        key: 'upstreams-empty',
        title: 'No upstreams configured',
        detail: 'Add at least one registry upstream before relying on policy evaluations.',
        tone: 'warning',
        to: '/upstreams',
        actionLabel: 'Add upstream',
      })
    }

    if (hasPoliciesError) {
      items.push({
        key: 'policies-error',
        title: 'Policy inventory unavailable',
        detail: 'The dashboard could not load policies for this tenant.',
        tone: 'warning',
        to: '/policies',
        actionLabel: 'View policies',
      })
    } else if (policies.length === 0) {
      items.push({
        key: 'policies-empty',
        title: 'No policies configured',
        detail: 'Create tenant policies so evaluations produce useful enforcement decisions.',
        tone: 'warning',
        to: '/policies',
        actionLabel: 'Create policy',
      })
    } else if (!policies.some((policy) => policy.enabled)) {
      items.push({
        key: 'policies-disabled',
        title: 'All policies are disabled',
        detail: 'Enable at least one policy before expecting enforcement decisions.',
        tone: 'warning',
        to: '/policies',
        actionLabel: 'Enable policy',
      })
    }
  }

  if (items.length === 0) {
    return [
      {
        key: 'clear',
        title: 'No policy matches in recent decisions',
        detail: 'Recent decisions did not include deny outcomes, warnings, degraded dependencies, or setup gaps.',
        tone: 'success',
      },
    ]
  }

  return items.slice(0, 6)
}

export function DashboardPage() {
  const api = useTenantControlPlaneApi()
  const { activeTenant, tenantId } = useTenant()
  const healthQuery = useHealth()
  const recentEvaluationsQuery = useRecentEvaluations(dashboardEvaluationsLimit)
  const upstreamsQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: upstreamsQueryKey(tenantId),
    queryFn: ({ signal }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before loading upstreams.')
      }

      return listUpstreams(api, tenantId, signal)
    },
  })
  const policiesQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: ['policies', tenantId],
    queryFn: async ({ signal }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before loading policies.')
      }

      const policies = await api.policies.list({ signal })
      return policies.map(asTypedPolicy).sort(sortPolicies)
    },
  })
  const recentEvaluations = recentEvaluationsQuery.data ?? []
  const upstreams = useMemo(() => sortUpstreams(upstreamsQuery.data ?? []), [upstreamsQuery.data])
  const policies = policiesQuery.data ?? []
  const evaluationSummary = summarizeEvaluations(recentEvaluations)
  const enabledPolicies = policies.filter((policy) => policy.enabled)
  const denyRate = formatPercent(evaluationSummary.denyCount, evaluationSummary.total)
  const cacheRate = formatPercent(evaluationSummary.cachedCount, evaluationSummary.total)
  const authenticatedUpstreams = upstreams.filter((upstream) => upstream.auth?.configured)
  const freshDecisionCount = evaluationSummary.total - evaluationSummary.cachedCount
  const attentionItems = buildAttentionItems(
    recentEvaluations,
    healthQuery.data,
    upstreams,
    policies,
    tenantId,
    upstreamsQuery.isError,
    policiesQuery.isError,
  )

  const summaryMetrics = [
    {
      label: 'Recent decisions',
      value: String(evaluationSummary.total),
      hint: `Latest ${dashboardEvaluationsLimit} results`,
    },
    {
      label: 'Denied',
      value: String(evaluationSummary.denyCount),
      hint: `${denyRate} of the recent window`,
      tone: 'danger',
    },
    {
      label: 'With warnings',
      value: String(evaluationSummary.warningCount),
      hint: 'Results with warning tags',
    },
    {
      label: 'Cache usage',
      value: cacheRate,
      hint: `${evaluationSummary.cachedCount} cached decisions`,
    },
  ] as const

  function refreshDashboard() {
    void healthQuery.refetch()
    void recentEvaluationsQuery.refetch()
    void upstreamsQuery.refetch()
    void policiesQuery.refetch()
  }

  return (
    <section className={evaluationClass("page")}>
      <header className={evaluationClass("page-header")}>
        <div>
          <p className={evaluationClass("eyebrow")}>Operator overview</p>
          <h2>Dashboard</h2>
          <p className={evaluationClass("page-summary")}>{activeTenant?.name ?? 'Selected tenant'} overview.</p>
        </div>
        <div className={evaluationClass("page-actions")}>
          {recentEvaluationsQuery.isFetching || upstreamsQuery.isFetching || policiesQuery.isFetching ? (
            <span className={evaluationClass("status-pill")}>Refreshing</span>
          ) : null}
          <button className={evaluationClass("secondary-button")} onClick={refreshDashboard} type="button">
            Refresh
          </button>
          <Link className={evaluationClass("route-link")} to="/evaluations">
            Open audit trail
          </Link>
        </div>
      </header>

      <div className={evaluationClass("dashboard-body-grid")}>
        <div className={evaluationClass("dashboard-primary-stack")}>
          <section className={evaluationClass("card dashboard-primary-card")}>
            <div className={evaluationClass("section-header")}>
              <div>
                <h3>Recent decisions</h3>
              </div>
              {recentEvaluations.length > 0 ? <Link className={evaluationClass("route-link")} to="/evaluations">
                Inspect
              </Link> : null}
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
                title="No decisions yet"
                message="Install a package through a configured upstream to see allow and deny decisions here."
              />
            ) : (
              <>
                <SummaryMetrics items={summaryMetrics} />
                <div className={evaluationClass("dashboard-chart-grid")}>
                  <DashboardCompactBar
                    label="Outcome split"
                    segments={[
                      { label: 'Allow', value: evaluationSummary.allowCount, tone: 'success' },
                      { label: 'Deny', value: evaluationSummary.denyCount, tone: 'danger' },
                      { label: 'Warnings', value: evaluationSummary.warningCount, tone: 'warning' },
                    ]}
                    total={evaluationSummary.total}
                  />
                  <DashboardCompactBar
                    label="Cache usage"
                    segments={[
                      { label: 'Cached', value: evaluationSummary.cachedCount, tone: 'success' },
                      { label: 'Fresh', value: freshDecisionCount },
                    ]}
                    total={evaluationSummary.total}
                  />
                </div>
              </>
            )}
          </section>

          <section className={evaluationClass("card dashboard-attention-card")}>
            <div className={evaluationClass("section-header")}>
              <div>
                <h3>Needs attention</h3>
              </div>
            </div>

            <ul className={evaluationClass("dashboard-attention-list")}>
              {attentionItems.map((item) => (
                <li key={item.key} className={evaluationClass('dashboard-attention-item', `dashboard-attention-item-${item.tone ?? 'default'}`)}>
                  <div>
                    <strong>{item.title}</strong>
                    <p className={evaluationClass("muted")}>{item.detail}</p>
                  </div>
                  {item.to ? (
                    <Link className={evaluationClass("route-link")} to={item.to}>
                      {item.actionLabel ?? 'Open'}
                    </Link>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>

          {recentEvaluations.length > 0 ? <section className={evaluationClass("card")}>
            <div className={evaluationClass("section-header")}>
              <div>
                <h3>Recent activity</h3>
              </div>
              <Link className={evaluationClass("route-link")} to="/evaluations">
                View all
              </Link>
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
            ) : recentEvaluations.length === 0 ? (
              <QueryStateNotice
                title="No evaluations recorded"
                message="This tenant does not have any stored evaluation history yet."
              />
            ) : (
              <div className={evaluationClass("dashboard-activity-table")}>
                <div className={evaluationClass("dashboard-activity-row dashboard-activity-head")}>
                  <span>Artifact</span>
                  <span>Outcome</span>
                  <span>Reason</span>
                  <span>Policy</span>
                  <span>Time</span>
                </div>
                {recentEvaluations.slice(0, 7).map((evaluation) => (
                  <div key={evaluation.id} className={evaluationClass("dashboard-activity-row")}>
                    <div>
                      <span className={evaluationClass("route-label")}>{evaluation.artifact.ecosystem}</span>
                      <strong>{formatArtifact(evaluation.artifact)}</strong>
                    </div>
                    <div className={evaluationClass("pill-group")}>
                      <span className={statusPillClassName(getOutcomeTone(evaluation.outcome))}>
                        {evaluation.outcome.toUpperCase()}
                      </span>
                      {evaluation.cached_at ? <span className={evaluationClass("status-pill status-pill-neutral")}>Cached</span> : null}
                    </div>
                    <p className={evaluationClass("muted")}>{getPrimaryReason(evaluation)}</p>
                    <span>{formatPolicyReference(evaluation)}</span>
                    <span className={evaluationClass("muted")}>{formatRelativeTime(evaluation.evaluated_at)}</span>
                  </div>
                ))}
              </div>
            )}
          </section> : null}
        </div>

        <div className={evaluationClass("dashboard-side-stack")}>
          <ControlPlaneHealthCard
            error={healthQuery.error}
            health={healthQuery.data}
            isLoading={healthQuery.isPending}
            onRetry={() => void healthQuery.refetch()}
            compact
          />

          <section className={evaluationClass("card")}>
            <div className={evaluationClass("section-header")}>
              <div>
                <h3>Configuration</h3>
              </div>
              <Link className={evaluationClass("route-link")} to="/upstreams">
                Manage
              </Link>
            </div>

            <dl className={evaluationClass("dashboard-coverage-list")}>
              <div>
                <dt>Registry upstreams</dt>
                <dd>{upstreamsQuery.isPending && tenantId ? 'Loading' : upstreams.length}</dd>
                <small>{authenticatedUpstreams.length} authenticated OCI upstreams</small>
              </div>
              <div>
                <dt>Policy coverage</dt>
                <dd>{policiesQuery.isPending && tenantId ? 'Loading' : `${enabledPolicies.length} enabled`}</dd>
                <small>{policies.length - enabledPolicies.length} disabled or draft policies</small>
              </div>
              <div>
                <dt>Recent policy spread</dt>
                <dd>{evaluationSummary.uniquePolicies}</dd>
                <small>policies represented in the recent window</small>
              </div>
              <div>
                <dt>Decision freshness</dt>
                <dd>{formatRelativeTime(evaluationSummary.latestEvaluatedAt)}</dd>
                <small>latest stored evaluation</small>
              </div>
            </dl>
          </section>
        </div>
      </div>
    </section>
  )
}
