// CreateUpstreamModal renders the tenant-scoped upstream creation wizard.
import type { FormEventHandler, RefObject } from 'react'
import { ModalWizard, type ModalWizardStep } from '../../components/modal/index.ts'
import {
  formatUpstreamCapabilityLabel,
  getUpstreamCapabilityDefinitions,
  upstreamBaseUrlExamples,
  upstreamEcosystems,
  type UpstreamCapability,
  type UpstreamDraft,
  type UpstreamDraftErrors,
} from './api.ts'

const createWizardSteps = [
  {
    id: 'connection',
    label: 'Connection',
    description: 'Choose the ecosystem, name, and URL.',
  },
  {
    id: 'review',
    label: 'Review',
    description: 'Confirm the tenant-scoped details.',
  },
] satisfies readonly ModalWizardStep[]

type CreateUpstreamModalProps = {
  open: boolean
  tenantId: string | null
  draft: UpstreamDraft
  draftErrors: UpstreamDraftErrors
  currentStep: number
  createErrorMessage: string
  isPending: boolean
  isError: boolean
  initialFocusRef: RefObject<HTMLInputElement | null>
  onBack: () => void
  onClose: () => void
  onDraftChange: (field: keyof UpstreamDraft, value: string) => void
  onCapabilityToggle: (capability: UpstreamCapability, checked: boolean) => void
  onReset: () => void
  onSubmit: FormEventHandler<HTMLFormElement>
}

function formatDraftCapabilities(draft: UpstreamDraft): string {
  return draft.capabilities.length > 0
    ? draft.capabilities.map((capability) => formatUpstreamCapabilityLabel(capability)).join(', ')
    : 'None selected'
}

export function CreateUpstreamModal({
  open,
  tenantId,
  draft,
  draftErrors,
  currentStep,
  createErrorMessage,
  isPending,
  isError,
  initialFocusRef,
  onBack,
  onClose,
  onDraftChange,
  onCapabilityToggle,
  onReset,
  onSubmit,
}: CreateUpstreamModalProps) {
  const aside = (
    <div className="upstreams-wizard-aside">
      <section className="upstreams-wizard-card">
        <p className="eyebrow">Tenant scope</p>
        <h3>Active tenant</h3>
        <p className="muted">
          Created for <code>{tenantId ?? 'the selected tenant'}</code> only.
        </p>
      </section>

      <section className="upstreams-wizard-card">
        <h3>Draft summary</h3>
        <dl className="upstreams-wizard-summary">
          <div>
            <dt>Name</dt>
            <dd>{draft.name.trim() || 'Not set yet'}</dd>
          </div>
          <div>
            <dt>Ecosystem</dt>
            <dd>{draft.ecosystem.toUpperCase()}</dd>
          </div>
          <div>
            <dt>Base URL</dt>
            <dd>{draft.baseUrl.trim() || upstreamBaseUrlExamples[draft.ecosystem]}</dd>
          </div>
          <div>
            <dt>Capabilities</dt>
            <dd>{formatDraftCapabilities(draft)}</dd>
          </div>
        </dl>
      </section>
    </div>
  )

  const footer = (
    <div className="upstreams-wizard-footer">
      <div className="upstreams-form-actions">
        <button
          className="upstreams-secondary-button"
          disabled={isPending}
          onClick={onClose}
          type="button"
        >
          Cancel
        </button>
        <button
          className="upstreams-secondary-button"
          disabled={isPending}
          onClick={onReset}
          type="button"
        >
          Reset
        </button>
      </div>

      <div className="upstreams-form-actions">
        {currentStep > 0 ? (
          <button
            className="upstreams-secondary-button"
            disabled={isPending}
            onClick={onBack}
            type="button"
          >
            Back
          </button>
        ) : null}

        {currentStep === 0 ? (
          <button
            className="primary-button"
            disabled={!tenantId || isPending}
            form="create-upstream-form"
            type="submit"
          >
            Review details
          </button>
        ) : (
          <button
            className="primary-button"
            disabled={isPending || !tenantId}
            form="create-upstream-form"
            type="submit"
          >
            {isPending ? 'Creating...' : 'Create upstream'}
          </button>
        )}
      </div>
    </div>
  )

  return (
    <ModalWizard
      aside={aside}
      closeOnEscape={!isPending}
      closeOnOverlayClick={!isPending}
      currentStep={currentStep}
      description="Create an npm or OCI upstream."
      dismissible={!isPending}
      footer={footer}
      headerMeta={
        <span className="status-pill status-pill-neutral">{tenantId ? `Tenant ${tenantId}` : 'No tenant selected'}</span>
      }
      initialFocusRef={initialFocusRef}
      onClose={onClose}
      open={open}
      size="wide"
      steps={createWizardSteps}
      title="Create upstream"
    >
      <form className="upstreams-form upstreams-modal-form" id="create-upstream-form" onSubmit={onSubmit}>
        {isError ? (
          <div className="upstreams-feedback upstreams-feedback-error" role="alert">
            <strong>Unable to create upstream</strong>
            <p>{createErrorMessage}</p>
          </div>
        ) : null}

        {currentStep === 0 ? (
          <div className="upstreams-wizard-section">
            <div className="upstreams-wizard-copy">
              <h3>Connection details</h3>
            </div>

            <div className={`upstreams-field${draftErrors.name ? ' upstreams-field-invalid' : ''}`}>
              <label htmlFor="upstream-name">Display name</label>
              <input
                aria-invalid={Boolean(draftErrors.name)}
                id="upstream-name"
                name="name"
                onChange={(event) => onDraftChange('name', event.target.value)}
                placeholder="docker-hub"
                ref={initialFocusRef}
                value={draft.name}
              />
              <small>Use a short operator-facing label for this upstream.</small>
              {draftErrors.name ? <p className="upstreams-field-error">{draftErrors.name}</p> : null}
            </div>

            <div className={`upstreams-field${draftErrors.ecosystem ? ' upstreams-field-invalid' : ''}`}>
              <label htmlFor="upstream-ecosystem">Ecosystem</label>
              <select
                aria-invalid={Boolean(draftErrors.ecosystem)}
                id="upstream-ecosystem"
                name="ecosystem"
                onChange={(event) => onDraftChange('ecosystem', event.target.value)}
                value={draft.ecosystem}
              >
                {upstreamEcosystems.map((ecosystem) => (
                  <option key={ecosystem} value={ecosystem}>
                    {ecosystem.toUpperCase()}
                  </option>
                ))}
              </select>
              <small>Duplicate registry URLs are blocked for the same tenant and ecosystem.</small>
              {draftErrors.ecosystem ? (
                <p className="upstreams-field-error">{draftErrors.ecosystem}</p>
              ) : null}
            </div>

            <div className={`upstreams-field${draftErrors.baseUrl ? ' upstreams-field-invalid' : ''}`}>
              <label htmlFor="upstream-base-url">Base URL</label>
              <input
                aria-invalid={Boolean(draftErrors.baseUrl)}
                id="upstream-base-url"
                name="baseUrl"
                onChange={(event) => onDraftChange('baseUrl', event.target.value)}
                placeholder={upstreamBaseUrlExamples[draft.ecosystem]}
                value={draft.baseUrl}
              />
              <small>Example: {upstreamBaseUrlExamples[draft.ecosystem]}</small>
              {draftErrors.baseUrl ? (
                <p className="upstreams-field-error">{draftErrors.baseUrl}</p>
              ) : null}
            </div>

            <fieldset className="upstreams-capability-group">
              <legend>Capability profile</legend>
              <p className="muted">Capabilities control which policy types can use this upstream.</p>
              <div className="upstreams-capability-list">
                {getUpstreamCapabilityDefinitions(draft.ecosystem).map((capability) => {
                  const checked = draft.capabilities.includes(capability.id)
                  return (
                    <label key={capability.id} className="upstreams-capability-option">
                      <input
                        checked={checked}
                        onChange={(event) => onCapabilityToggle(capability.id, event.target.checked)}
                        type="checkbox"
                      />
                      <span>
                        <strong>{capability.label}</strong>
                        <small>{capability.description}</small>
                      </span>
                    </label>
                  )
                })}
              </div>
            </fieldset>
          </div>
        ) : (
          <div className="upstreams-wizard-section">
            <div className="upstreams-wizard-copy">
              <h3>Review upstream</h3>
            </div>

            <div className="upstreams-review-card">
              <dl className="upstreams-detail upstreams-review-list">
                <div>
                  <dt>Tenant</dt>
                  <dd>
                    <code>{tenantId ?? 'No tenant selected'}</code>
                  </dd>
                </div>
                <div>
                  <dt>Name</dt>
                  <dd>{draft.name.trim()}</dd>
                </div>
                <div>
                  <dt>Ecosystem</dt>
                  <dd>{draft.ecosystem.toUpperCase()}</dd>
                </div>
                <div>
                  <dt>Base URL</dt>
                  <dd>{draft.baseUrl.trim()}</dd>
                </div>
                <div>
                  <dt>Capabilities</dt>
                  <dd>{formatDraftCapabilities(draft)}</dd>
                </div>
              </dl>
            </div>
          </div>
        )}
      </form>
    </ModalWizard>
  )
}
