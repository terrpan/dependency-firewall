// Upstream page panels keep registry list, detail, and usage rendering out of the route component.
import type { Upstream } from '../../lib/api/types.ts'
import { formatUpstreamAuth, formatUpstreamHost } from './model.ts'
import type { UpstreamUsageGuide } from './usage.ts'
import { upstreamClass } from './styles.ts'

type UpstreamsListPanelProps = {
  upstreams: readonly Upstream[]
  selectedUpstreamId: string | null
  isLoading: boolean
  isError: boolean
  isSuccess: boolean
  errorMessage: string
  createDisabled: boolean
  onCreate: () => void
  onRetry: () => void
  onSelect: (upstreamId: string) => void
}

export function UpstreamsListPanel({
  upstreams,
  selectedUpstreamId,
  isLoading,
  isError,
  isSuccess,
  errorMessage,
  createDisabled,
  onCreate,
  onRetry,
  onSelect,
}: UpstreamsListPanelProps) {
  return (
    <section className={upstreamClass("card upstreams-panel")}>
      <div className={upstreamClass("upstreams-panel-header")}>
        <div>
          <h3>Configured upstreams</h3>
        </div>
        {isLoading ? <span className={upstreamClass("status-pill")}>Loading</span> : null}
      </div>

      {isError ? (
        <div className={upstreamClass("upstreams-feedback upstreams-feedback-error")} role="alert">
          <strong>Unable to load upstreams</strong>
          <p>{errorMessage}</p>
          <button className={upstreamClass("upstreams-secondary-button")} onClick={onRetry} type="button">
            Retry
          </button>
        </div>
      ) : null}

      {isSuccess && upstreams.length === 0 ? (
        <div className={upstreamClass("upstreams-empty-state")}>
          <h3>Connect the first package source</h3>
          <p className={upstreamClass("muted")}>
            Add the registry your team already uses. You will get tenant-specific npm or Docker setup as soon as it is connected.
          </p>
          <div className={upstreamClass("upstreams-form-actions")}>
            <button className={upstreamClass("primary-button")} disabled={createDisabled} onClick={onCreate} type="button">
              Create upstream
            </button>
          </div>
        </div>
      ) : null}

      {upstreams.length > 0 ? (
        <div className={upstreamClass("upstreams-list")} role="list" aria-label="Configured upstreams">
          {upstreams.map((upstream) => {
            const isActive = upstream.id === selectedUpstreamId

            return (
              <button
                key={upstream.id}
                className={upstreamClass('upstreams-list-item', isActive && 'is-active')}
                onClick={() => onSelect(upstream.id)}
                type="button"
              >
                <div className={upstreamClass("upstreams-selection-meta")}>
                  <span className={upstreamClass("upstreams-badge")}>{upstream.ecosystem}</span>
                  {isActive ? <span className={upstreamClass("status-pill status-pill-neutral")}>Selected</span> : null}
                </div>
                <strong>{upstream.name}</strong>
                <span className={upstreamClass("upstreams-list-host")}>{formatUpstreamHost(upstream)}</span>
                <span className={upstreamClass("upstreams-list-summary")}>
                  <span>{formatUpstreamAuth(upstream)}</span>
                  <span>
                    {(upstream.supported_policy_types ?? []).length}{' '}
                    {(upstream.supported_policy_types ?? []).length === 1 ? 'policy type' : 'policy types'} available
                  </span>
                </span>
              </button>
            )
          })}
        </div>
      ) : null}
    </section>
  )
}

type UpstreamDetailsPanelProps = {
  upstream: Upstream | null
  capabilities: readonly string[]
  policyTypes: readonly string[]
  isDeleting: boolean
  isConfirmingDelete: boolean
  onCancelDelete: () => void
  onConfirmDelete: (upstream: Upstream) => void
  onRequestDelete: (upstream: Upstream) => void
  formatTimestamp: (value: string) => string
}

export function UpstreamDetailsPanel({
  upstream,
  capabilities,
  policyTypes,
  isDeleting,
  isConfirmingDelete,
  onCancelDelete,
  onConfirmDelete,
  onRequestDelete,
  formatTimestamp,
}: UpstreamDetailsPanelProps) {
  return (
    <section className={upstreamClass("card upstreams-panel")}>
      <div className={upstreamClass("upstreams-panel-header")}>
        <div>
          <p className={upstreamClass("upstreams-section-label")}>Package source</p>
          <h3>{upstream?.name ?? 'Upstream details'}</h3>
        </div>
        {upstream ? <span className={upstreamClass("upstreams-badge")}>{upstream.ecosystem}</span> : null}
      </div>

      {upstream ? (
        <div className={upstreamClass("upstreams-detail-content")}>
          <dl className={upstreamClass("upstreams-detail upstreams-operational-detail")}>
            <div>
              <dt>Source URL</dt>
              <dd>
                <a className={upstreamClass("inline-link")} href={upstream.base_url} target="_blank" rel="noreferrer">
                  {upstream.base_url}
                </a>
              </dd>
            </div>
            <div>
              <dt>Credentials</dt>
              <dd>{formatUpstreamAuth(upstream)}</dd>
            </div>
            <div>
              <dt>Policy data</dt>
              <dd>{capabilities.length > 0 ? capabilities.join(', ') : 'No enrichment data'}</dd>
            </div>
            <div>
              <dt>Available policy types</dt>
              <dd>{policyTypes.length > 0 ? policyTypes.join(', ') : 'No capability-dependent policy types'}</dd>
            </div>
          </dl>

          <details className={upstreamClass("upstreams-metadata-disclosure")}>
            <summary>Technical details</summary>
            <dl className={upstreamClass("upstreams-detail")}>
              <div><dt>Identifier</dt><dd><code>{upstream.id}</code></dd></div>
              <div><dt>Authentication type</dt><dd>{upstream.auth?.type ?? 'none'}</dd></div>
              <div><dt>Created</dt><dd>{formatTimestamp(upstream.created_at)}</dd></div>
              <div><dt>Updated</dt><dd>{formatTimestamp(upstream.updated_at)}</dd></div>
            </dl>
          </details>

          <div className={upstreamClass("upstreams-delete-zone")}>
            {isConfirmingDelete ? (
              <div className={upstreamClass("upstreams-delete-confirmation")} role="alert">
                <div>
                  <strong>Remove {upstream.name}?</strong>
                  <p>Requests can no longer use this package source. Policies scoped to it may also need attention.</p>
                </div>
                <div className={upstreamClass("upstreams-form-actions")}>
                  <button className={upstreamClass("upstreams-secondary-button")} disabled={isDeleting} onClick={onCancelDelete} type="button">
                    Cancel
                  </button>
                  <button className={upstreamClass("upstreams-secondary-button upstreams-danger-button")} disabled={isDeleting} onClick={() => onConfirmDelete(upstream)} type="button">
                    {isDeleting ? 'Removing...' : 'Remove upstream'}
                  </button>
                </div>
              </div>
            ) : (
              <button className={upstreamClass("upstreams-secondary-button upstreams-danger-button")} onClick={() => onRequestDelete(upstream)} type="button">
                Remove upstream
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className={upstreamClass("upstreams-empty-state")}>
          <h3>No detail selected</h3>
          <p className={upstreamClass("muted")}>Pick an upstream from the list, or create the first one in the modal flow.</p>
        </div>
      )}
    </section>
  )
}

type UpstreamUsagePanelProps = {
  upstream: Upstream | null
  usage: UpstreamUsageGuide | null
  copiedUsageKey: string | null
  copyErrorMessage: string | null
  onCopyUsage: (code: string, key: string) => void
}

export function UpstreamUsagePanel({
  upstream,
  usage,
  copiedUsageKey,
  copyErrorMessage,
  onCopyUsage,
}: UpstreamUsagePanelProps) {
  return (
    <section className={upstreamClass("card upstreams-panel")}>
      <div className={upstreamClass("upstreams-panel-header")}>
        <div>
          <h3>{usage?.title ?? 'Usage instructions'}</h3>
          {usage ? <p>{usage.summary}</p> : null}
        </div>
      </div>

      {upstream && usage ? (
        <div className={upstreamClass("upstreams-usage-guide")}>
          <div className={upstreamClass("upstreams-usage-section")}>
            <div className={upstreamClass("upstreams-usage-header")}>
              <span className={upstreamClass("upstreams-usage-label")}>{usage.primaryLabel}</span>
              <button
                aria-label={`Copy ${usage.primaryLabel}`}
                className={upstreamClass("upstreams-copy-button")}
                onClick={() => onCopyUsage(usage.primaryCode, `${upstream.id}:primary`)}
                type="button"
              >
                {copiedUsageKey === `${upstream.id}:primary` ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre aria-label={`${usage.primaryLabel} command`} className={upstreamClass("code-block")} tabIndex={0}>{usage.primaryCode}</pre>
          </div>

          <div className={upstreamClass("upstreams-usage-section")}>
            <div className={upstreamClass("upstreams-usage-header")}>
              <span className={upstreamClass("upstreams-usage-label")}>{usage.secondaryLabel}</span>
              <button
                aria-label={`Copy ${usage.secondaryLabel}`}
                className={upstreamClass("upstreams-copy-button")}
                onClick={() => onCopyUsage(usage.secondaryCode, `${upstream.id}:secondary`)}
                type="button"
              >
                {copiedUsageKey === `${upstream.id}:secondary` ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre aria-label={`${usage.secondaryLabel} command`} className={upstreamClass("code-block")} tabIndex={0}>{usage.secondaryCode}</pre>
          </div>

          {copyErrorMessage ? (
            <div className={upstreamClass("upstreams-feedback upstreams-feedback-error")} role="alert">
              <p>{copyErrorMessage}</p>
            </div>
          ) : null}

          <p className={upstreamClass("muted")}>{usage.note}</p>
        </div>
      ) : (
        <div className={upstreamClass("upstreams-empty-state")}>
          <h3>No usage instructions yet</h3>
          <p className={upstreamClass("muted")}>Pick an upstream first so the page can show npm or Docker guidance.</p>
        </div>
      )}
    </section>
  )
}
