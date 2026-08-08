import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  QueryStateNotice,
  SummaryMetrics,
} from '../features/evaluations/components.tsx'
import { dashboardEvaluationsLimit, useRecentEvaluations } from '../features/evaluations/api.ts'
import {
  formatArtifact,
  formatRelativeTime,
  formatPolicyReference,
  getOutcomeTone,
  getPrimaryReason,
  getQueryErrorMessage,
  summarizeEvaluations,
} from '../features/evaluations/model.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { useTenantControlPlaneApi } from '../features/tenant/useTenantControlPlaneApi.ts'
import {
  listUpstreams,
  sortUpstreams,
  upstreamsQueryKey,
} from '../features/upstreams/api.ts'
import { asTypedPolicy, type Evaluation, type TypedPolicy, type Upstream } from '../lib/api/index.ts'
import { sortPolicies } from '../features/policies/display.ts'
import { dashboardClass } from '../features/dashboard/styles.ts'

type AttentionItem = {
  key: string
  title: string
  detail: string
  tone?: 'danger' | 'warning' | 'success'
  to?: string
  actionLabel?: string
}

function statusPillClassName(tone: 'default' | 'success' | 'danger' | 'warning' | undefined) {
  return dashboardClass(
    'status-pill',
    tone === 'success' && 'status-pill-success',
    tone === 'danger' && 'status-pill-danger',
    tone === 'warning' && 'status-pill-warning',
  )
}

function formatPercent(numerator: number, denominator: number) {
  if (denominator === 0) {
    return '0%'
  }

  return `${Math.round((numerator / denominator) * 100)}%`
}

function buildAttentionItems(
  evaluations: readonly Evaluation[],
  upstreams: readonly Upstream[],
  policies: readonly TypedPolicy[],
  tenantId: string | null,
  hasUpstreamsError: boolean,
  hasPoliciesError: boolean,
): AttentionItem[] {
  const items: AttentionItem[] = []

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
    } else if (!policies.some((policy) => policy.enabled && policy.config.dry_run !== true)) {
      items.push({
        key: 'policies-not-enforcing',
        title: 'No policy is enforcing',
        detail: policies.some((policy) => policy.enabled)
          ? 'Every enabled policy is in dry-run mode. Promote a reviewed policy to begin enforcement.'
          : 'Enable at least one policy before expecting enforcement decisions.',
        tone: 'warning',
        to: '/policies',
        actionLabel: 'Review policies',
      })
    }
  }

  const deniedEvaluations = evaluations.filter((evaluation) => evaluation.outcome.toLowerCase() === 'deny')
  for (const evaluation of deniedEvaluations.slice(0, 2)) {
    items.push({
      key: `deny-${evaluation.id}`,
      title: `${formatArtifact(evaluation.artifact)} was blocked`,
      detail: getPrimaryReason(evaluation),
      tone: 'warning',
      to: '/evaluations',
      actionLabel: 'Review decision',
    })
  }

  const warningEvaluation = evaluations.find((evaluation) => (evaluation.warnings?.length ?? 0) > 0)
  if (warningEvaluation) {
    items.push({
      key: `warning-${warningEvaluation.id}`,
      title: 'A recent decision has warnings',
      detail: `${formatArtifact(warningEvaluation.artifact)} recorded ${warningEvaluation.warnings?.length ?? 0} warning${warningEvaluation.warnings?.length === 1 ? '' : 's'}.`,
      tone: 'warning',
      to: '/evaluations',
      actionLabel: 'Review decision',
    })
  }

  if (items.length === 0) {
    return [
      {
        key: 'clear',
        title: 'No action required',
        detail: 'Protection is configured and recent decisions have no blocks, warnings, or service issues to review.',
        tone: 'success',
      },
    ]
  }

  return items.slice(0, 6)
}

export function DashboardPage() {
  const api = useTenantControlPlaneApi()
  const { activeTenant, tenantId } = useTenant()
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
  const enforcingPolicies = enabledPolicies.filter((policy) => policy.config.dry_run !== true)
  const dryRunPolicies = enabledPolicies.length - enforcingPolicies.length
  const denyRate = formatPercent(evaluationSummary.denyCount, evaluationSummary.total)
  const attentionItems = buildAttentionItems(
    recentEvaluations,
    upstreams,
    policies,
    tenantId,
    upstreamsQuery.isError,
    policiesQuery.isError,
  )
  const attentionIsClear = attentionItems.length === 1 && attentionItems[0]?.tone === 'success'
  const attentionTone = attentionIsClear
    ? 'success'
    : attentionItems.some((item) => item.tone === 'danger') ? 'danger' : 'warning'

  const summaryMetrics = [
    {
      label: 'Decisions reviewed',
      value: recentEvaluationsQuery.isPending ? '—' : String(evaluationSummary.total),
      hint: `Latest ${dashboardEvaluationsLimit} decisions`,
    },
    {
      label: 'Blocked',
      value: recentEvaluationsQuery.isPending ? '—' : String(evaluationSummary.denyCount),
      hint: evaluationSummary.total > 0 ? `${denyRate} of recent decisions` : 'No recent decisions',
      tone: evaluationSummary.denyCount > 0 ? 'danger' : undefined,
    },
    {
      label: 'Enforcing policies',
      value: policiesQuery.isPending && tenantId ? '—' : String(enforcingPolicies.length),
      hint: `${dryRunPolicies} dry run · ${policies.length - enabledPolicies.length} disabled`,
      tone: enforcingPolicies.length > 0 ? undefined : 'warning',
    },
    {
      label: 'Registry upstreams',
      value: upstreamsQuery.isPending && tenantId ? '—' : String(upstreams.length),
      hint: upstreams.length === 1 ? '1 package source configured' : `${upstreams.length} package sources configured`,
      tone: upstreams.length > 0 ? undefined : 'warning',
    },
  ] as const

  function refreshDashboard() {
    void recentEvaluationsQuery.refetch()
    void upstreamsQuery.refetch()
    void policiesQuery.refetch()
  }

  return (
    <section className={dashboardClass("page")}>
      <header className={dashboardClass("page-header")}>
        <div>
          <p className={dashboardClass("eyebrow")}>Protection overview</p>
          <h2>Dashboard</h2>
          <p className={dashboardClass("page-summary")}>
            See what is protected, what was blocked, and what needs your attention for {activeTenant?.name ?? 'the selected tenant'}.
          </p>
        </div>
        <div className={dashboardClass("page-actions")}>
          {recentEvaluationsQuery.isFetching || upstreamsQuery.isFetching || policiesQuery.isFetching ? (
            <span className={dashboardClass("status-pill")}>Refreshing</span>
          ) : null}
          <button className={dashboardClass("secondary-button")} onClick={refreshDashboard} type="button">
            Refresh
          </button>
          <Link className={dashboardClass("route-link")} to="/evaluations">
            Review all decisions
          </Link>
        </div>
      </header>

      <SummaryMetrics items={summaryMetrics} />

      <div className={dashboardClass("dashboard-body-grid")}>
        <div className={dashboardClass("dashboard-primary-stack")}>
          <section className={dashboardClass("card dashboard-attention-card")}>
            <div className={dashboardClass("section-header")}>
              <div>
                <h3>Needs attention</h3>
                <p className={dashboardClass("muted")}>Start here. Items are ordered by operational impact.</p>
              </div>
              <span className={statusPillClassName(attentionTone)}>
                {attentionIsClear ? 'Clear' : `${attentionItems.length} to review`}
              </span>
            </div>

            <ul className={dashboardClass("dashboard-attention-list")}>
              {attentionItems.map((item) => (
                <li key={item.key} className={dashboardClass('dashboard-attention-item', `dashboard-attention-item-${item.tone ?? 'default'}`)}>
                  <div>
                    <strong>{item.title}</strong>
                    <p className={dashboardClass("muted")}>{item.detail}</p>
                  </div>
                  {item.to ? (
                    <Link className={dashboardClass("route-link")} to={item.to}>
                      {item.actionLabel ?? 'Open'}
                    </Link>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>

          <section className={dashboardClass("card")}>
            <div className={dashboardClass("section-header")}>
              <div>
                <h3>Latest decisions</h3>
                <p className={dashboardClass("muted")}>The most recent package checks and why they were allowed or blocked.</p>
              </div>
              <Link className={dashboardClass("route-link")} to="/evaluations">
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
              <div className={dashboardClass("dashboard-activity-table")}>
                <div className={dashboardClass("dashboard-activity-row dashboard-activity-head")}>
                  <span>Artifact</span>
                  <span>Outcome</span>
                  <span>Reason</span>
                  <span>Policy</span>
                  <span>Time</span>
                </div>
                {recentEvaluations.slice(0, 5).map((evaluation) => (
                  <div key={evaluation.id} className={dashboardClass("dashboard-activity-row")}>
                    <div>
                      <span className={dashboardClass("route-label")}>{evaluation.artifact.ecosystem}</span>
                      <strong>{formatArtifact(evaluation.artifact)}</strong>
                    </div>
                    <div>
                      <span className={dashboardClass("dashboard-mobile-label")}>Outcome</span>
                      <div className={dashboardClass("pill-group")}>
                        <span className={statusPillClassName(getOutcomeTone(evaluation.outcome))}>
                          {evaluation.outcome.toUpperCase()}
                        </span>
                        {evaluation.cached_at ? <span className={dashboardClass("status-pill status-pill-neutral")}>Cached</span> : null}
                      </div>
                    </div>
                    <div>
                      <span className={dashboardClass("dashboard-mobile-label")}>Reason</span>
                      <p className={dashboardClass("muted")}>{getPrimaryReason(evaluation)}</p>
                    </div>
                    <span><span className={dashboardClass("dashboard-mobile-label")}>Policy</span>{formatPolicyReference(evaluation)}</span>
                    <span className={dashboardClass("muted")}><span className={dashboardClass("dashboard-mobile-label")}>Time</span>{formatRelativeTime(evaluation.evaluated_at)}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>

        <div className={dashboardClass("dashboard-side-stack")}>
          <section className={dashboardClass("card")}>
            <div className={dashboardClass("section-header")}>
              <div>
                <h3>Protection readiness</h3>
                <p className={dashboardClass("muted")}>The minimum setup required for active enforcement.</p>
              </div>
            </div>

            <ol className={dashboardClass("dashboard-readiness-list")}>
              <li>
                <span className={statusPillClassName(tenantId ? 'success' : 'warning')}>{tenantId ? 'Ready' : 'Required'}</span>
                <div>
                  <strong>Tenant selected</strong>
                  <p className={dashboardClass("muted")}>{activeTenant?.name ?? 'Choose the tenant to protect.'}</p>
                </div>
                <Link className={dashboardClass("route-link")} to="/tenants">Manage tenant</Link>
              </li>
              <li>
                <span className={statusPillClassName(upstreams.length > 0 ? 'success' : 'warning')}>{upstreams.length > 0 ? 'Ready' : 'Required'}</span>
                <div>
                  <strong>Package source connected</strong>
                  <p className={dashboardClass("muted")}>
                    {upstreams.length > 0 ? `${upstreams.length} upstream${upstreams.length === 1 ? '' : 's'} configured.` : 'Add the registry packages will be installed through.'}
                  </p>
                </div>
                <Link className={dashboardClass("route-link")} to="/upstreams">Manage upstreams</Link>
              </li>
              <li>
                <span className={statusPillClassName(enforcingPolicies.length > 0 ? 'success' : 'warning')}>{enforcingPolicies.length > 0 ? 'Ready' : 'Required'}</span>
                <div>
                  <strong>Policy enforcement active</strong>
                  <p className={dashboardClass("muted")}>
                    {enforcingPolicies.length > 0 ? `${enforcingPolicies.length} polic${enforcingPolicies.length === 1 ? 'y is' : 'ies are'} enforcing.` : 'Enable a reviewed policy outside dry-run mode.'}
                  </p>
                </div>
                <Link className={dashboardClass("route-link")} to="/policies">Manage policies</Link>
              </li>
              <li>
                <span className={statusPillClassName(recentEvaluations.length > 0 ? 'success' : 'warning')}>{recentEvaluations.length > 0 ? 'Active' : 'Waiting'}</span>
                <div>
                  <strong>Decision traffic</strong>
                  <p className={dashboardClass("muted")}>
                    {recentEvaluations.length > 0 ? `Latest decision ${formatRelativeTime(evaluationSummary.latestEvaluatedAt)}.` : 'Install a package through an upstream to verify the path.'}
                  </p>
                </div>
                <Link className={dashboardClass("route-link")} to="/evaluations">Review decisions</Link>
              </li>
            </ol>
          </section>
        </div>
      </div>
    </section>
  )
}
