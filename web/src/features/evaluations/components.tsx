import type { Evaluation } from '../../lib/api/index.ts'
import { evaluationClass } from './styles.ts'
import {
  formatArtifact,
  formatCachedAt,
  formatNamespace,
  formatPolicyId,
  formatPolicyReference,
  formatRelativeTime,
  formatReasonPolicyLabel,
  formatTimestamp,
  getOutcomeTone,
  hasDryRunWarning,
  getPrimaryReason,
  shortenHash,
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
    <div className={evaluationClass('metric-grid')}>
      {items.map((item) => (
        <article key={item.label} className={toneClassName('metric-card', item.tone)}>
          <span className={evaluationClass('metric-label')}>{item.label}</span>
          <strong className={evaluationClass('metric-value')}>{item.value}</strong>
          {item.hint ? <p className={evaluationClass('muted')}>{item.hint}</p> : null}
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

export function QueryStateNotice({ title, message, actionLabel = 'Retry', onAction }: QueryStateNoticeProps) {
  return (
    <div className={evaluationClass('state-notice')}>
      <div>
        <strong>{title}</strong>
        <p className={evaluationClass('muted')}>{message}</p>
      </div>
      {onAction ? (
        <div className={evaluationClass('button-row')}>
          <button className={evaluationClass('secondary-button')} onClick={onAction} type="button">
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
    <ul
      aria-label="Evaluation decisions"
      className={evaluationClass('evaluation-list', compact && 'evaluation-list-compact')}
    >
      {evaluations.map((evaluation) => {
        const primaryReason = getPrimaryReason(evaluation)
        const matchedReasons = (evaluation.reasons ?? []).filter(
          (reason) => reason.message !== primaryReason || reason.policy_id !== evaluation.policy_id,
        )
        const warningTags = evaluation.warnings ?? []
        const isDryRun = hasDryRunWarning(evaluation)

        return (
          <li key={evaluation.id} className={evaluationClass('evaluation-item')}>
            <div className={evaluationClass('evaluation-header')}>
              <div className={evaluationClass('stack-sm')}>
                <p className={evaluationClass('route-label')}>{evaluation.artifact.ecosystem}</p>
                <h4 className={evaluationClass('evaluation-title')}>{formatArtifact(evaluation.artifact)}</h4>
                <p className={evaluationClass('muted')}>
                  {formatTimestamp(evaluation.evaluated_at)} · {formatRelativeTime(evaluation.evaluated_at)}
                </p>
              </div>

              <div className={evaluationClass('pill-group')}>
                <StatusPill label={evaluation.outcome.toUpperCase()} tone={getOutcomeTone(evaluation.outcome)} />
                {isDryRun ? <StatusPill label="DRY RUN" tone="warning" /> : null}
                {evaluation.cached_at ? <StatusPill label="CACHED" /> : null}
              </div>
            </div>

            <p className={evaluationClass('evaluation-reason')}>{primaryReason}</p>

            <p className={evaluationClass('evaluation-policy')}>
              <span>Policy</span>
              <strong>{formatPolicyReference(evaluation)}</strong>
            </p>

            {!compact ? (
              <details className={evaluationClass('evaluation-disclosure')}>
                <summary>Decision details</summary>
                <div className={evaluationClass('evaluation-detail-content')}>
                  {warningTags.length > 0 ? (
                    <div className={evaluationClass('evaluation-warning')}>
                      <strong>Dry-run warnings</strong>
                      <ul>
                        {warningTags.map((warning) => (
                          <li key={`${evaluation.id}-${warning}`}>{warning}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  {matchedReasons.length > 0 ? (
                    <div className={evaluationClass('evaluation-matches')}>
                      <strong>Other matched policies</strong>
                      <ul className={evaluationClass('detail-list')}>
                        {matchedReasons.map((reason) => (
                          <li key={`${evaluation.id}-${reason.policy_id}-${reason.category}-${reason.message}`}>
                            <strong>{formatReasonPolicyLabel(reason)}</strong> · {reason.action} · {reason.message}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  <dl className={evaluationClass('detail-grid')}>
                    <div>
                      <dt>Evaluation ID</dt>
                      <dd>
                        <code>{evaluation.id}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Policy ID</dt>
                      <dd>
                        <code>{formatPolicyId(evaluation)}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Policy hash</dt>
                      <dd>
                        <code>{shortenHash(evaluation.policy_hash, 18)}</code>
                      </dd>
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
                </div>
              </details>
            ) : warningTags.length > 0 ? (
              <span className={evaluationClass('tag')}>
                {warningTags.length} warning{warningTags.length > 1 ? 's' : ''}
              </span>
            ) : null}
          </li>
        )
      })}
    </ul>
  )
}
