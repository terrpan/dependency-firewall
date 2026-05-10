// Upstream page panels keep registry list, detail, and usage rendering out of the route component.
import type { Upstream } from '../../lib/api/types.ts'
import type { UpstreamUsageGuide } from './usage.ts'

type UpstreamsListPanelProps = {
  upstreams: readonly Upstream[]
  selectedUpstreamId: string | null
  isLoading: boolean
  isError: boolean
  isSuccess: boolean
  errorMessage: string
  createDisabled: boolean
  onCreate: () => void
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
  onSelect,
}: UpstreamsListPanelProps) {
  return (
    <section className="card upstreams-panel">
      <div className="upstreams-panel-header">
        <div>
          <h3>Configured upstreams</h3>
          <p>Registry endpoints for the active tenant.</p>
        </div>
        {isLoading ? <span className="status-pill">Loading</span> : null}
      </div>

      {isError ? (
        <div className="upstreams-feedback upstreams-feedback-error" role="alert">
          <strong>Unable to load upstreams</strong>
          <p>{errorMessage}</p>
        </div>
      ) : null}

      {isSuccess && upstreams.length === 0 ? (
        <div className="upstreams-empty-state">
          <h3>No upstreams configured yet</h3>
          <p className="muted">Create the first upstream without leaving this page context.</p>
          <div className="upstreams-form-actions">
            <button className="primary-button" disabled={createDisabled} onClick={onCreate} type="button">
              Create upstream
            </button>
          </div>
        </div>
      ) : null}

      {upstreams.length > 0 ? (
        <div className="upstreams-list" role="list" aria-label="Configured upstreams">
          {upstreams.map((upstream) => {
            const isActive = upstream.id === selectedUpstreamId

            return (
              <button
                key={upstream.id}
                className={`upstreams-list-item${isActive ? ' is-active' : ''}`}
                onClick={() => onSelect(upstream.id)}
                type="button"
              >
                <div className="upstreams-selection-meta">
                  <span className="upstreams-badge">{upstream.ecosystem}</span>
                  {isActive ? <span className="status-pill status-pill-neutral">Selected</span> : null}
                </div>
                <strong>{upstream.name}</strong>
                <small>{upstream.base_url}</small>
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
  onDelete: (upstream: Upstream) => void
  formatTimestamp: (value: string) => string
}

export function UpstreamDetailsPanel({
  upstream,
  capabilities,
  policyTypes,
  isDeleting,
  onDelete,
  formatTimestamp,
}: UpstreamDetailsPanelProps) {
  return (
    <section className="card upstreams-panel">
      <div className="upstreams-panel-header">
        <div>
          <h3>Upstream details</h3>
          <p>Inspect the selected registry endpoint.</p>
        </div>
        {upstream ? (
          <div className="upstreams-panel-actions">
            <span className="upstreams-badge">{upstream.ecosystem}</span>
            <button
              className="upstreams-secondary-button upstreams-danger-button"
              disabled={isDeleting}
              onClick={() => onDelete(upstream)}
              type="button"
            >
              {isDeleting ? 'Deleting...' : 'Delete upstream'}
            </button>
          </div>
        ) : null}
      </div>

      {upstream ? (
        <dl className="upstreams-detail">
          <div>
            <dt>Name</dt>
            <dd>{upstream.name}</dd>
          </div>
          <div>
            <dt>Identifier</dt>
            <dd>
              <code>{upstream.id}</code>
            </dd>
          </div>
          <div>
            <dt>Base URL</dt>
            <dd>
              <a className="inline-link" href={upstream.base_url} target="_blank" rel="noreferrer">
                {upstream.base_url}
              </a>
            </dd>
          </div>
          <div>
            <dt>Capabilities</dt>
            <dd>{capabilities.length > 0 ? capabilities.join(', ') : 'None'}</dd>
          </div>
          <div>
            <dt>Supported policies</dt>
            <dd>{policyTypes.length > 0 ? policyTypes.join(', ') : 'None'}</dd>
          </div>
          <div>
            <dt>Authentication</dt>
            <dd>
              {upstream.auth?.configured
                ? upstream.auth.username
                  ? `${upstream.auth.type} (${upstream.auth.username})`
                  : upstream.auth.type
                : 'Unauthenticated'}
            </dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd>{formatTimestamp(upstream.created_at)}</dd>
          </div>
          <div>
            <dt>Updated</dt>
            <dd>{formatTimestamp(upstream.updated_at)}</dd>
          </div>
        </dl>
      ) : (
        <div className="upstreams-empty-state">
          <h3>No detail selected</h3>
          <p className="muted">Pick an upstream from the list, or create the first one in the modal flow.</p>
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
    <section className="card upstreams-panel">
      <div className="upstreams-panel-header">
        <div>
          <h3>{usage?.title ?? 'Usage instructions'}</h3>
          <p>
            {usage?.summary ?? 'Select an upstream to see how developers should use it from npm or Docker.'}
          </p>
        </div>
      </div>

      {upstream && usage ? (
        <div className="upstreams-usage-guide">
          <div className="upstreams-usage-section">
            <div className="upstreams-usage-header">
              <span className="upstreams-usage-label">{usage.primaryLabel}</span>
              <button
                className="upstreams-copy-button"
                onClick={() => onCopyUsage(usage.primaryCode, `${upstream.id}:primary`)}
                type="button"
              >
                {copiedUsageKey === `${upstream.id}:primary` ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="code-block">{usage.primaryCode}</pre>
          </div>

          <div className="upstreams-usage-section">
            <div className="upstreams-usage-header">
              <span className="upstreams-usage-label">{usage.secondaryLabel}</span>
              <button
                className="upstreams-copy-button"
                onClick={() => onCopyUsage(usage.secondaryCode, `${upstream.id}:secondary`)}
                type="button"
              >
                {copiedUsageKey === `${upstream.id}:secondary` ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="code-block">{usage.secondaryCode}</pre>
          </div>

          {copyErrorMessage ? (
            <div className="upstreams-feedback upstreams-feedback-error" role="alert">
              <p>{copyErrorMessage}</p>
            </div>
          ) : null}

          <p className="muted">{usage.note}</p>
        </div>
      ) : (
        <div className="upstreams-empty-state">
          <h3>No usage instructions yet</h3>
          <p className="muted">Pick an upstream first so the page can show npm or Docker guidance.</p>
        </div>
      )}
    </section>
  )
}
