// PolicyDetailModal renders policy overview and retained version history.
import { ModalDialog } from '../../components/modal/index.ts'
import type { TypedPolicy, TypedPolicyVersion, Upstream } from '../../lib/api/index.ts'
import { getPolicyTypeLabel, isPolicyDryRun } from './draft.ts'
import {
  formatPolicyScopeLabel,
  formatPolicyTimestamp,
  getActionTone,
  getEnabledTone,
  getPolicyConfigDetail,
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

  return (
    <ModalDialog
      closeLabel="Close policy details"
      description={policy ? `${currentPolicyTypeLabel} • current version ${policy.version}` : undefined}
      dismissible={!isRollbackPending}
      eyebrow="Policy details"
      headerMeta={
        policy && detailTab === 'history' ? (
          <span className="status-pill status-pill-neutral">Retention limit 3</span>
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
        <div className="policy-history-modal">
          <div className="policy-detail-tabs" aria-label="Policy detail views">
            <button
              aria-pressed={detailTab === 'overview'}
              className={`policy-detail-tab${detailTab === 'overview' ? ' active' : ''}`}
              onClick={() => onDetailTabChange('overview')}
              type="button"
            >
              Overview
            </button>
            <button
              aria-pressed={detailTab === 'history'}
              className={`policy-detail-tab${detailTab === 'history' ? ' active' : ''}`}
              onClick={() => onDetailTabChange('history')}
              type="button"
            >
              History
            </button>
          </div>

          <section className="policy-current-card">
            <div className="policy-current-header">
              <div className="policy-list-item-badges">
                <span className={`policy-badge ${getActionTone(policy.action)}`}>{policy.action}</span>
                <span className={`policy-badge ${getEnabledTone(policy.enabled)}`}>
                  {policy.enabled ? 'enabled' : 'disabled'}
                </span>
                {isPolicyDryRun(policy) ? (
                  <span className="policy-badge policy-badge-muted">dry run</span>
                ) : null}
              </div>
              <div className="policy-current-actions">
                <div className="policy-list-item-actions">
                  <button
                    className="policy-card-action policy-card-action-danger"
                    disabled={policy.enabled || Boolean(deletePendingPolicyId)}
                    onClick={() => onDelete(policy)}
                    title={policy.enabled ? 'Disable the policy before deleting it.' : undefined}
                    type="button"
                  >
                    {policy.enabled ? 'Disable first' : isDeletePending ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
                <div className="policy-inline-toggle">
                  <span className="policy-inline-toggle-label">Enabled</span>
                  <button
                    className={`policy-enabled-toggle${policy.enabled ? ' active' : ''}`}
                    disabled={isTogglePending}
                    onClick={() => onTogglePolicy(policy)}
                    type="button"
                  >
                    {isTogglePending ? 'Saving...' : policy.enabled ? 'true' : 'false'}
                  </button>
                </div>
              </div>
            </div>

            {isDeleteError ? (
              <div className="policy-error-panel">
                <h4>Unable to delete policy</h4>
                <p className="muted">{deleteErrorMessage}</p>
              </div>
            ) : null}

            <div className="policy-config-summary">
              <span className="policy-config-label">{getPolicyConfigDetail(policy).label}</span>
              <span className="policy-config-value">{getPolicyConfigDetail(policy).value}</span>
            </div>
            <dl className="metadata-list compact-metadata-list">
              <div>
                <dt>Policy id</dt>
                <dd>
                  <code>{policy.id}</code>
                </dd>
              </div>
              <div>
                <dt>Scope</dt>
                <dd>{formatPolicyScopeLabel(policy, upstreamsByID)}</dd>
              </div>
              <div>
                <dt>Created</dt>
                <dd>{formatPolicyTimestamp(policy.created_at)}</dd>
              </div>
              <div>
                <dt>Schema</dt>
                <dd>v{policy.schema_version}</dd>
              </div>
              <div>
                <dt>Priority</dt>
                <dd>{policy.priority}</dd>
              </div>
              <div>
                <dt>Updated</dt>
                <dd>{formatPolicyTimestamp(policy.updated_at)}</dd>
              </div>
            </dl>
          </section>

          {detailTab === 'overview' ? (
            <section className="policy-metadata-card">
              <h4>Configuration</h4>
              <div className="policy-config-field-list">
                {getPolicyConfigFields(policy).map((field) => (
                  <div key={field.label} className="policy-config-field-card">
                    <span className="policy-config-field-label">{field.label}</span>
                    {field.values.length === 1 ? (
                      <strong className="policy-config-field-value">{field.values[0]}</strong>
                    ) : (
                      <div className="policy-config-chip-row">
                        {field.values.map((value) => (
                          <span key={value} className="policy-chip">
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
                <div className="policy-error-panel">
                  <h4>Unable to load policy versions</h4>
                  <p className="muted">{versionsErrorMessage}</p>
                </div>
              ) : null}

              {isVersionsPending ? (
                <div className="policy-empty-state">
                  <h4>Loading history</h4>
                  <p className="muted">Pulling retained versions for this policy.</p>
                </div>
              ) : null}

              {!isVersionsPending && !isVersionsError && versions.length === 0 ? (
                <div className="policy-empty-state">
                  <h4>No retained versions yet</h4>
                  <p className="muted">
                    Version history appears after the first update or rollback snapshot is stored by the backend.
                  </p>
                </div>
              ) : null}

              <div className="policy-history-list">
                {versions.map((version) => (
                  <article key={version.version} className="policy-history-item">
                    <div className="policy-history-item-header">
                      <div>
                        <h4>Version {version.version}</h4>
                        <p className="muted">{formatPolicyTimestamp(version.created_at)}</p>
                      </div>
                      <div className="policy-history-actions">
                        <button className="policy-card-action" onClick={() => onOpenDiff(version)} type="button">
                          Compare
                        </button>
                        <button
                          className="secondary-button"
                          disabled={isRollbackPending}
                          onClick={() => onRollback(policy.id, version.version)}
                          type="button"
                        >
                          Roll back
                        </button>
                      </div>
                    </div>
                    <div className="policy-list-item-badges">
                      <span className={`policy-badge ${getActionTone(version.action)}`}>{version.action}</span>
                      <span className={`policy-badge ${getEnabledTone(version.enabled)}`}>
                        {version.enabled ? 'enabled' : 'disabled'}
                      </span>
                      {isPolicyDryRun(version) ? <span className="policy-badge policy-badge-muted">dry run</span> : null}
                    </div>
                    <div className="policy-config-field-list policy-config-field-list-compact">
                      {getPolicyConfigFields(version).map((field) => (
                        <div key={field.label} className="policy-config-field-card">
                          <span className="policy-config-field-label">{field.label}</span>
                          {field.values.length === 1 ? (
                            <strong className="policy-config-field-value">{field.values[0]}</strong>
                          ) : (
                            <div className="policy-config-chip-row">
                              {field.values.map((value) => (
                                <span key={value} className="policy-chip">
                                  {value}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                    <dl className="metadata-list compact-metadata-list">
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
                <div className="policy-error-panel">
                  <h4>Rollback request failed</h4>
                  <p className="muted">{rollbackErrorMessage}</p>
                </div>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}
    </ModalDialog>
  )
}
