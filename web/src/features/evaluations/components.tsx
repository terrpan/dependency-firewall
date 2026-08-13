import type { Evaluation, Health } from '../../lib/api/index.ts'
import { evaluationClass } from './styles.ts'
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
    return evaluationClass(baseClassName, `${baseClassName}-success`)
  }

  if (tone === 'danger') {
    return evaluationClass(baseClassName, `${baseClassName}-danger`)
  }

  if (tone === 'warning') {
    return evaluationClass(baseClassName, `${baseClassName}-warning`)
  }

  return evaluationClass(baseClassName)
}

function StatusPill({ label, tone }: { label: string; tone?: Tone }) {
  return <span className={toneClassName('status-pill', tone)}>{label}</span>
}

export function SummaryMetrics({ items }: { items: readonly SummaryMetric[] }) {
  return (
    <div className={evaluationClass("metric-grid")}>
      {items.map((item) => (
        <article key={item.label} className={toneClassName('metric-card', item.tone)}>
          <span className={evaluationClass("metric-label")}>{item.label}</span>
          <strong className={evaluationClass("metric-value")}>{item.value}</strong>
          {item.hint ? <p className={evaluationClass("muted")}>{item.hint}</p> : null}
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
    <div className={evaluationClass("state-notice")}>
      <div>
        <strong>{title}</strong>
        <p className={evaluationClass("muted")}>{message}</p>
      </div>
      {onAction ? (
        <div className={evaluationClass("button-row")}>
          <button className={evaluationClass("secondary-button")} onClick={onAction} type="button">
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
    <ul className={evaluationClass('evaluation-list', compact && 'evaluation-list-compact')}>
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
          <li key={evaluation.id} className={evaluationClass("evaluation-item")}>
            <div className={evaluationClass("evaluation-header")}>
              <div className={evaluationClass("stack-sm")}>
                <p className={evaluationClass("route-label")}>{evaluation.artifact.ecosystem}</p>
                <h4 className={evaluationClass("evaluation-title")}>{formatArtifact(evaluation.artifact)}</h4>
                <p className={evaluationClass("muted")}>
                  {formatTimestamp(evaluation.evaluated_at)} · {formatRelativeTime(evaluation.evaluated_at)}
                </p>
              </div>

              <div className={evaluationClass("pill-group")}>
                <StatusPill label={evaluation.outcome.toUpperCase()} tone={getOutcomeTone(evaluation.outcome)} />
                {isDryRun ? <StatusPill label="DRY RUN" tone="warning" /> : null}
                {evaluation.cached_at ? <StatusPill label="CACHED" /> : null}
              </div>
            </div>

            <p className={evaluationClass("evaluation-reason")}>{primaryReason}</p>

            {matchedReasons.length > 0 && !compact ? (
              <ul className={evaluationClass("detail-list")}>
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
              <div className={evaluationClass("tag-list")}>
                {compact ? (
                  <span className={evaluationClass("tag")}>{warningTags.length} warning{warningTags.length > 1 ? 's' : ''}</span>
                ) : (
                  warningTags.map((warning) => (
                    <span key={`${evaluation.id}-${warning}`} className={evaluationClass("tag")}>
                      {warning}
                    </span>
                  ))
                )}
              </div>
            ) : null}

            {!compact ? (
              <dl className={evaluationClass("detail-grid")}>
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
  compact?: boolean
}

export function ControlPlaneHealthCard({
  health,
  isLoading,
  error,
  onRetry,
  compact = false,
}: ControlPlaneHealthCardProps) {
  if (isLoading) {
    return (
      <section className={evaluationClass("card")}>
        <div className={evaluationClass("section-header")}>
          <div>
            <h3>{compact ? 'Health' : 'Control-plane status'}</h3>
            {!compact ? <p className={evaluationClass("muted")}>Loading health and dependency status.</p> : null}
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
      <section className={evaluationClass("card")}>
        <div className={evaluationClass("section-header")}>
          <div>
            <h3>{compact ? 'Health' : 'Control-plane status'}</h3>
            {!compact ? <p className={evaluationClass("muted")}>Health and dependency status.</p> : null}
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
    <section className={evaluationClass("card")}>
      <div className={evaluationClass("section-header")}>
        <div>
          <h3>{compact ? 'Health' : 'Control-plane status'}</h3>
          {!compact ? <p className={evaluationClass("muted")}>Health and dependency status.</p> : null}
        </div>
        <StatusPill label={health.status.toUpperCase()} tone={getStatusTone(health.status)} />
      </div>

      {!compact ? (
        <dl className={evaluationClass("detail-grid")}>
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
      ) : null}

      {total > 0 ? (
        <>
          {!compact ? (
            <p className={evaluationClass("muted")}>
              {degradedCount === 0
                ? `${total} dependencies are healthy.`
                : `${degradedCount} of ${total} dependencies need review.`}
            </p>
          ) : null}

          <ul className={evaluationClass("dependency-list")}>
            {dependencies.map(([name, dependency]) => (
              <li key={name} className={evaluationClass("dependency-item")}>
                <div>
                  <strong>{name}</strong>
                  <p className={evaluationClass("muted")}>
                    {dependency.message?.trim() || `Checked ${formatRelativeTime(dependency.timestamp)}.`}
                  </p>
                </div>

                <div className={evaluationClass("dependency-meta")}>
                  <StatusPill label={dependency.status.toUpperCase()} tone={getStatusTone(dependency.status)} />
                  <span className={evaluationClass("muted")}>{formatDuration(dependency.duration_ms)}</span>
                </div>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className={evaluationClass("muted")}>The health payload did not include dependency details.</p>
      )}
    </section>
  )
}
