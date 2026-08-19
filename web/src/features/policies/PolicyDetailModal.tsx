// PolicyDetailModal renders policy overview and retained version history.
import { ModalDialog } from '../../components/modal/index.ts'
import { policyClass } from './styles.ts'
import type { TypedPolicy, TypedPolicyVersion, Upstream } from '../../lib/api/index.ts'
import { getPolicyTypeLabel, isPolicyDryRun } from './draft.ts'
import {
  formatPolicyScopeLabel,
  formatPolicyTimestamp,
  formatPolicyActionLabel,
  getPolicyBehaviorSummary,
  getPolicyTargetSummary,
  getActionTone,
  getEnabledTone,
  getPolicyConfigFields,
} from './display.ts'

export type PolicyDetailTab = 'overview' | 'history'

type PolicyDetailModalProps = {
  policy: TypedPolicy | null
  detailTab: PolicyDetailTab
  upstreamsByID: Map<string, Upstream>
  versions: readonly TypedPolicyVersion[]
  isOpen: boolean
  hasOpenDiff: boolean
  isVersionsPending: boolean
  isVersionsError: boolean
  versionsErrorMessage: string | null
  isRollbackPending: boolean
  isRollbackError: boolean
  rollbackErrorMessage: string | null
  isDeleteError: boolean
  deleteErrorMessage: string
  deletePendingPolicyId: string | null
  togglePendingPolicyId: string | null
  onClose: () => void
  onDetailTabChange: (tab: PolicyDetailTab) => void
  onDelete: (policy: TypedPolicy) => void
  onTogglePolicy: (policy: TypedPolicy) => void
  onOpenDiff: (version: TypedPolicyVersion) => void
  onRollback: (policyId: string, version: number) => void
}

export function PolicyDetailModal({
  policy,
  detailTab,
  upstreamsByID,
  versions,
  isOpen,
  hasOpenDiff,
  isVersionsPending,
  isVersionsError,
  versionsErrorMessage,
  isRollbackPending,
  isRollbackError,
  rollbackErrorMessage,
  isDeleteError,
  deleteErrorMessage,
  deletePendingPolicyId,
  togglePendingPolicyId,
  onClose,
  onDetailTabChange,
  onDelete,
  onTogglePolicy,
  onOpenDiff,
  onRollback,
}: PolicyDetailModalProps) {
  const currentPolicyTypeLabel = policy ? getPolicyTypeLabel(policy.type) : null
  const isDeletePending = Boolean(policy && deletePendingPolicyId === policy.id)
  const isTogglePending = Boolean(policy && togglePendingPolicyId === policy.id)
  const isCurrentPolicyDryRun = Boolean(policy && isPolicyDryRun(policy))

  return (
    <ModalDialog
      closeLabel="Close policy details"
      description={policy ? `${currentPolicyTypeLabel} • current version ${policy.version}` : undefined}
      dismissible={!isRollbackPending}
      eyebrow="Policy details"
      headerMeta={
        policy && detailTab === 'history' ? (
          <span className={policyClass('status-pill status-pill-neutral')}>Retention limit 3</span>
        ) : null
      }
      closeOnEscape={!hasOpenDiff}
      closeOnOverlayClick={!hasOpenDiff}
      onClose={onClose}
      open={isOpen && Boolean(policy)}
      size="wide"
      title={policy ? policy.name : 'Policy details'}
    >
      {policy ? (
        <div className={policyClass('policy-history-modal')}>
          <div className={policyClass('policy-detail-tabs')} aria-label="Policy detail views">
            <button
              aria-pressed={detailTab === 'overview'}
              className={policyClass('policy-detail-tab', detailTab === 'overview' && 'active')}
              onClick={() => onDetailTabChange('overview')}
              type="button"
            >
              Overview
            </button>
            <button
              aria-pressed={detailTab === 'history'}
              className={policyClass('policy-detail-tab', detailTab === 'history' && 'active')}
              onClick={() => onDetailTabChange('history')}
              type="button"
            >
              History
            </button>
          </div>

          <section className={policyClass('policy-current-card')}>
            <div className={policyClass('policy-current-header')}>
              <div className={policyClass('policy-list-item-badges')}>
                <span
                  className={policyClass(
                    'policy-badge',
                    !policy.enabled
                      ? 'policy-badge-muted'
                      : isCurrentPolicyDryRun
                        ? 'policy-badge-warning'
                        : 'policy-badge-success',
                  )}
                >
                  {!policy.enabled ? 'Disabled' : isCurrentPolicyDryRun ? 'Dry run' : 'Enforcing'}
                </span>
                <span className={policyClass('policy-badge', getActionTone(policy.action))}>
                  {formatPolicyActionLabel(policy.action)}
                </span>
              </div>
              <div className={policyClass('policy-current-actions')}>
                <div className={policyClass('policy-list-item-actions')}>
                  {!policy.enabled ? (
                    <button
                      className={policyClass('policy-card-action policy-card-action-danger')}
                      disabled={Boolean(deletePendingPolicyId)}
                      onClick={() => onDelete(policy)}
                      type="button"
                    >
                      {isDeletePending ? 'Deleting...' : 'Delete'}
                    </button>
                  ) : null}
                </div>
                <div className={policyClass('policy-list-state-actions')}>
                  <button
                    aria-label={`${policy.enabled ? 'Disable' : 'Enable'} ${policy.name}`}
                    className={policyClass('policy-card-action policy-state-action')}
                    disabled={isTogglePending}
                    onClick={() => onTogglePolicy(policy)}
                    type="button"
                  >
                    {isTogglePending ? 'Saving...' : policy.enabled ? 'Disable' : 'Enable'}
                  </button>
                </div>
              </div>
            </div>

            {isDeleteError ? (
              <div className={policyClass('policy-error-panel')}>
                <h4>Unable to delete policy</h4>
                <p className={policyClass('muted')}>{deleteErrorMessage}</p>
              </div>
            ) : null}

            <div className={policyClass('policy-behavior-summary')}>
              <span className={policyClass('policy-config-label')}>What it does</span>
              <strong>{getPolicyBehaviorSummary(policy)}</strong>
            </div>
            <dl className={policyClass('policy-overview-grid')}>
              <div>
                <dt>Applies through</dt>
                <dd>{formatPolicyScopeLabel(policy, upstreamsByID)}</dd>
              </div>
              <div>
                <dt>Dependencies</dt>
                <dd>{getPolicyTargetSummary(policy)}</dd>
              </div>
              <div>
                <dt>Evaluation order</dt>
                <dd>Priority {policy.priority}</dd>
              </div>
            </dl>
            <details className={policyClass('policy-metadata-disclosure')}>
              <summary>Technical details</summary>
              <dl className={policyClass('metadata-list compact-metadata-list')}>
                <div>
                  <dt>Policy id</dt>
                  <dd>
                    <code>{policy.id}</code>
                  </dd>
                </div>
                <div>
                  <dt>Schema</dt>
                  <dd>v{policy.schema_version}</dd>
                </div>
                <div>
                  <dt>Version</dt>
                  <dd>{policy.version}</dd>
                </div>
                <div>
                  <dt>Created</dt>
                  <dd>{formatPolicyTimestamp(policy.created_at)}</dd>
                </div>
                <div>
                  <dt>Updated</dt>
                  <dd>{formatPolicyTimestamp(policy.updated_at)}</dd>
                </div>
              </dl>
            </details>
          </section>

          {detailTab === 'overview' ? (
            <section className={policyClass('policy-metadata-card')}>
              <h4>Configuration</h4>
              <div className={policyClass('policy-config-field-list')}>
                {getPolicyConfigFields(policy).map((field) => (
                  <div key={field.label} className={policyClass('policy-config-field-card')}>
                    <span className={policyClass('policy-config-field-label')}>{field.label}</span>
                    {field.values.length === 1 ? (
                      <strong className={policyClass('policy-config-field-value')}>{field.values[0]}</strong>
                    ) : (
                      <div className={policyClass('policy-config-chip-row')}>
                        {field.values.map((value) => (
                          <span key={value} className={policyClass('policy-chip')}>
                            {value}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          ) : null}

          {detailTab === 'history' ? (
            <>
              {isVersionsError ? (
                <div className={policyClass('policy-error-panel')}>
                  <h4>Unable to load policy versions</h4>
                  <p className={policyClass('muted')}>{versionsErrorMessage}</p>
                </div>
              ) : null}

              {isVersionsPending ? (
                <div className={policyClass('policy-empty-state')}>
                  <h4>Loading history</h4>
                  <p className={policyClass('muted')}>Pulling retained versions for this policy.</p>
                </div>
              ) : null}

              {!isVersionsPending && !isVersionsError && versions.length === 0 ? (
                <div className={policyClass('policy-empty-state')}>
                  <h4>No retained versions yet</h4>
                  <p className={policyClass('muted')}>
                    Version history appears after the first update or rollback snapshot is stored by the backend.
                  </p>
                </div>
              ) : null}

              <div className={policyClass('policy-history-list')}>
                {versions.map((version) => (
                  <article key={version.version} className={policyClass('policy-history-item')}>
                    <div className={policyClass('policy-history-item-header')}>
                      <div>
                        <h4>Version {version.version}</h4>
                        <p className={policyClass('muted')}>{formatPolicyTimestamp(version.created_at)}</p>
                      </div>
                      <div className={policyClass('policy-history-actions')}>
                        <button
                          className={policyClass('policy-card-action')}
                          onClick={() => onOpenDiff(version)}
                          type="button"
                        >
                          Compare
                        </button>
                        <button
                          className={policyClass('secondary-button')}
                          disabled={isRollbackPending}
                          onClick={() => onRollback(policy.id, version.version)}
                          type="button"
                        >
                          Roll back
                        </button>
                      </div>
                    </div>
                    <div className={policyClass('policy-list-item-badges')}>
                      <span className={policyClass('policy-badge', getActionTone(version.action))}>
                        {formatPolicyActionLabel(version.action)}
                      </span>
                      <span className={policyClass('policy-badge', getEnabledTone(version.enabled))}>
                        {version.enabled ? 'enabled' : 'disabled'}
                      </span>
                      {isPolicyDryRun(version) ? (
                        <span className={policyClass('policy-badge policy-badge-muted')}>dry run</span>
                      ) : null}
                    </div>
                    <div className={policyClass('policy-config-field-list policy-config-field-list-compact')}>
                      {getPolicyConfigFields(version).map((field) => (
                        <div key={field.label} className={policyClass('policy-config-field-card')}>
                          <span className={policyClass('policy-config-field-label')}>{field.label}</span>
                          {field.values.length === 1 ? (
                            <strong className={policyClass('policy-config-field-value')}>{field.values[0]}</strong>
                          ) : (
                            <div className={policyClass('policy-config-chip-row')}>
                              {field.values.map((value) => (
                                <span key={value} className={policyClass('policy-chip')}>
                                  {value}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                    <dl className={policyClass('metadata-list compact-metadata-list')}>
                      <div>
                        <dt>Scope</dt>
                        <dd>{formatPolicyScopeLabel(version, upstreamsByID)}</dd>
                      </div>
                      <div>
                        <dt>Schema</dt>
                        <dd>v{version.schema_version}</dd>
                      </div>
                      <div>
                        <dt>Priority</dt>
                        <dd>{version.priority}</dd>
                      </div>
                      <div>
                        <dt>Type</dt>
                        <dd>{getPolicyTypeLabel(version.type)}</dd>
                      </div>
                    </dl>
                  </article>
                ))}
              </div>

              {isRollbackError ? (
                <div className={policyClass('policy-error-panel')}>
                  <h4>Rollback request failed</h4>
                  <p className={policyClass('muted')}>{rollbackErrorMessage}</p>
                </div>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}
    </ModalDialog>
  )
}
