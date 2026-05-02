import type { Evaluation, Health } from '../../lib/api/index.ts'
import {
  formatArtifact,
  formatCachedAt,
  formatDuration,
  formatNamespace,
  formatPolicyId,
  formatPolicyReference,
  formatRelativeTime,
  formatReasonPolicyLabel,
  formatTimestamp,
  getOutcomeTone,
  hasDryRunWarning,
  getPrimaryReason,
  getQueryErrorMessage,
  getStatusTone,
  shortenHash,
  summarizeDependencies,
  type Tone,
} from './model.ts'

export type SummaryMetric = {
  label: string
  value: string
  hint?: string
  tone?: Tone
}

function toneClassName(baseClassName: string, tone: Tone | undefined): string {
  if (tone === 'success') {
    return `${baseClassName} ${baseClassName}-success`
  }

  if (tone === 'danger') {
    return `${baseClassName} ${baseClassName}-danger`
  }

  if (tone === 'warning') {
    return `${baseClassName} ${baseClassName}-warning`
  }

  return baseClassName
}

function StatusPill({ label, tone }: { label: string; tone?: Tone }) {
  return <span className={toneClassName('status-pill', tone)}>{label}</span>
}

export function SummaryMetrics({ items }: { items: readonly SummaryMetric[] }) {
  return (
    <div className="metric-grid">
      {items.map((item) => (
        <article key={item.label} className={toneClassName('metric-card', item.tone)}>
          <span className="metric-label">{item.label}</span>
          <strong className="metric-value">{item.value}</strong>
          {item.hint ? <p className="muted">{item.hint}</p> : null}
        </article>
      ))}
    </div>
  )
}

type QueryStateNoticeProps = {
  title: string
  message: string
  actionLabel?: string
  onAction?: () => void
}

export function QueryStateNotice({
  title,
  message,
  actionLabel = 'Retry',
  onAction,
}: QueryStateNoticeProps) {
  return (
    <div className="state-notice">
      <div>
        <strong>{title}</strong>
        <p className="muted">{message}</p>
      </div>
      {onAction ? (
        <div className="button-row">
          <button className="secondary-button" onClick={onAction} type="button">
            {actionLabel}
          </button>
        </div>
      ) : null}
    </div>
  )
}

type EvaluationListProps = {
  evaluations: readonly Evaluation[]
  compact?: boolean
  emptyTitle?: string
  emptyMessage?: string
}

export function EvaluationList({
  evaluations,
  compact = false,
  emptyTitle = 'No evaluations recorded',
  emptyMessage = 'This tenant has no stored evaluation history yet.',
}: EvaluationListProps) {
  if (evaluations.length === 0) {
    return <QueryStateNotice title={emptyTitle} message={emptyMessage} />
  }

  return (
    <ul className={compact ? 'evaluation-list evaluation-list-compact' : 'evaluation-list'}>
      {evaluations.map((evaluation) => {
        const primaryReason = getPrimaryReason(evaluation)
        const matchedReasons = (evaluation.reasons ?? []).filter(
          (reason) =>
            reason.message !== primaryReason ||
            reason.policy_id !== evaluation.policy_id,
        )
        const warningTags = evaluation.warnings ?? []
        const isDryRun = hasDryRunWarning(evaluation)

        return (
          <li key={evaluation.id} className="evaluation-item">
            <div className="evaluation-header">
              <div className="stack-sm">
                <p className="route-label">{evaluation.artifact.ecosystem}</p>
                <h4 className="evaluation-title">{formatArtifact(evaluation.artifact)}</h4>
                <p className="muted">
                  {formatTimestamp(evaluation.evaluated_at)} · {formatRelativeTime(evaluation.evaluated_at)}
                </p>
              </div>

              <div className="pill-group">
                <StatusPill label={evaluation.outcome.toUpperCase()} tone={getOutcomeTone(evaluation.outcome)} />
                {isDryRun ? <StatusPill label="DRY RUN" tone="warning" /> : null}
                {evaluation.cached_at ? <StatusPill label="CACHED" /> : null}
              </div>
            </div>

            <p className="evaluation-reason">{primaryReason}</p>

            {matchedReasons.length > 0 && !compact ? (
              <ul className="detail-list">
                {matchedReasons.slice(0, 3).map((reason) => (
                  <li
                    key={`${evaluation.id}-${reason.policy_id}-${reason.category}-${reason.message}`}
                  >
                    <strong>{formatReasonPolicyLabel(reason)}</strong> · {reason.action} ·{' '}
                    {reason.message}
                  </li>
                ))}
                {matchedReasons.length > 3 ? (
                  <li>+{matchedReasons.length - 3} more matched reasons</li>
                ) : null}
              </ul>
            ) : null}

            {warningTags.length > 0 ? (
              <div className="tag-list">
                {compact ? (
                  <span className="tag">{warningTags.length} warning{warningTags.length > 1 ? 's' : ''}</span>
                ) : (
                  warningTags.map((warning) => (
                    <span key={`${evaluation.id}-${warning}`} className="tag">
                      {warning}
                    </span>
                  ))
                )}
              </div>
            ) : null}

            {!compact ? (
              <dl className="detail-grid">
                <div>
                  <dt>Policy</dt>
                  <dd>{formatPolicyReference(evaluation)}</dd>
                </div>
                <div>
                  <dt>Policy hash</dt>
                  <dd>{shortenHash(evaluation.policy_hash, 18)}</dd>
                </div>
                <div>
                  <dt>Policy ID</dt>
                  <dd>{formatPolicyId(evaluation)}</dd>
                </div>
                <div>
                  <dt>Namespace / scope</dt>
                  <dd>{formatNamespace(evaluation.artifact)}</dd>
                </div>
                <div>
                  <dt>Cached result</dt>
                  <dd>{formatCachedAt(evaluation.cached_at)}</dd>
                </div>
              </dl>
            ) : null}
          </li>
        )
      })}
    </ul>
  )
}

type ControlPlaneHealthCardProps = {
  health?: Health
  isLoading: boolean
  error?: unknown
  onRetry: () => void
}

export function ControlPlaneHealthCard({
  health,
  isLoading,
  error,
  onRetry,
}: ControlPlaneHealthCardProps) {
  if (isLoading) {
    return (
      <section className="card">
        <div className="section-header">
          <div>
            <h3>Control-plane status</h3>
            <p className="muted">Loading compact health and dependency status from /healthz.</p>
          </div>
          <StatusPill label="Loading" />
        </div>
        <QueryStateNotice
          title="Checking service status"
          message="Waiting for the control-plane health endpoint to respond."
        />
      </section>
    )
  }

  if (!health || error) {
    return (
      <section className="card">
        <div className="section-header">
          <div>
            <h3>Control-plane status</h3>
            <p className="muted">Compact health and dependency status from /healthz.</p>
          </div>
          <StatusPill label="Unavailable" tone="danger" />
        </div>
        <QueryStateNotice
          title="Unable to load health status"
          message={getQueryErrorMessage(error, 'The control-plane health endpoint did not return a response.')}
          onAction={onRetry}
        />
      </section>
    )
  }

  const { dependencies, degradedCount, total } = summarizeDependencies(health)

  return (
    <section className="card">
      <div className="section-header">
        <div>
          <h3>Control-plane status</h3>
          <p className="muted">Compact health and dependency status from /healthz.</p>
        </div>
        <StatusPill label={health.status.toUpperCase()} tone={getStatusTone(health.status)} />
      </div>

      <dl className="detail-grid">
        <div>
          <dt>Service</dt>
          <dd>{health.service_name}</dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd>{health.version}</dd>
        </div>
        <div>
          <dt>Commit</dt>
          <dd>{shortenHash(health.commit, 12)}</dd>
        </div>
        <div>
          <dt>Updated</dt>
          <dd>{formatTimestamp(health.timestamp)}</dd>
        </div>
        <div>
          <dt>Runtime</dt>
          <dd>
            {health.os}/{health.arch} · {health.go_version}
          </dd>
        </div>
        <div>
          <dt>Build time</dt>
          <dd>{health.build_time ? formatTimestamp(health.build_time) : '—'}</dd>
        </div>
      </dl>

      {total > 0 ? (
        <>
          <p className="muted">
            {degradedCount === 0
              ? `${total} dependencies are reporting healthy or ready.`
              : `${degradedCount} of ${total} dependencies need operator attention.`}
          </p>

          <ul className="dependency-list">
            {dependencies.map(([name, dependency]) => (
              <li key={name} className="dependency-item">
                <div>
                  <strong>{name}</strong>
                  <p className="muted">
                    {dependency.message?.trim() || `Checked ${formatRelativeTime(dependency.timestamp)}.`}
                  </p>
                </div>

                <div className="dependency-meta">
                  <StatusPill label={dependency.status.toUpperCase()} tone={getStatusTone(dependency.status)} />
                  <span className="muted">{formatDuration(dependency.duration_ms)}</span>
                </div>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="muted">The health payload did not include dependency details.</p>
      )}
    </section>
  )
}
