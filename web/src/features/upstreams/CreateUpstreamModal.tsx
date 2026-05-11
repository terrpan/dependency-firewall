// CreateUpstreamModal renders the tenant-scoped upstream creation wizard.
import type { FormEventHandler, RefObject } from 'react'
import { ModalWizard, type ModalWizardStep } from '../../components/modal/index.ts'
import {
  formatUpstreamCapabilityLabel,
  getUpstreamAuthTypes,
  getUpstreamCapabilityDefinitions,
  upstreamEcosystemSupportsAuthType,
  upstreamEcosystemSupportsAuth,
  upstreamBaseUrlExamples,
  upstreamEcosystems,
  upstreamNameExamples,
  type UpstreamCapability,
  type UpstreamAuthType,
  type UpstreamDraft,
  type UpstreamDraftErrors,
} from './api.ts'

const connectionStep = {
  id: 'connection',
  label: 'Connection',
  description: 'Choose the ecosystem, name, and URL.',
} satisfies ModalWizardStep

const authStep = {
  id: 'auth',
  label: 'Authentication',
  description: 'Configure OCI registry credentials.',
} satisfies ModalWizardStep

const reviewStep = {
  id: 'review',
  label: 'Review',
  description: 'Confirm the tenant-scoped details.',
} satisfies ModalWizardStep

const createWizardStepsWithAuth = [connectionStep, authStep, reviewStep] satisfies readonly ModalWizardStep[]
const createWizardStepsWithoutAuth = [connectionStep, reviewStep] satisfies readonly ModalWizardStep[]

function getCreateWizardSteps(draft: UpstreamDraft): readonly ModalWizardStep[] {
  return upstreamEcosystemSupportsAuth(draft.ecosystem) ? createWizardStepsWithAuth : createWizardStepsWithoutAuth
}

const authTypeLabels: Record<UpstreamAuthType, string> = {
  none: 'Unauthenticated',
  basic: 'Username / password or PAT',
  bearer_token: 'Bearer token',
}

function getAuthTypeOptions(draft: UpstreamDraft) {
  return getUpstreamAuthTypes(draft.ecosystem).map((authType) => ({
    value: authType,
    label: authTypeLabels[authType],
  }))
}

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

function formatDraftAuth(draft: UpstreamDraft): string {
  if (!upstreamEcosystemSupportsAuthType(draft.ecosystem, draft.authType) || draft.authType === 'none') {
    return 'Unauthenticated'
  }
  if (draft.authType === 'basic') {
    return draft.authUsername.trim() ? `Basic as ${draft.authUsername.trim()}` : 'Basic'
  }
  return 'Bearer token'
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
  const wizardSteps = getCreateWizardSteps(draft)
  const authTypeOptions = getAuthTypeOptions(draft)
  const activeStep = wizardSteps[Math.min(currentStep, wizardSteps.length - 1)] ?? reviewStep
  const isReviewStep = activeStep.id === 'review'
  const isAuthStep = activeStep.id === 'auth'
  const nextLabel =
    activeStep.id === 'connection' && upstreamEcosystemSupportsAuth(draft.ecosystem)
      ? 'Configure auth'
      : 'Review details'

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

        {!isReviewStep ? (
          <button
            className="primary-button"
            disabled={!tenantId || isPending}
            form="create-upstream-form"
            type="submit"
          >
            {nextLabel}
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
      closeOnEscape={!isPending}
      closeOnOverlayClick={!isPending}
      currentStep={currentStep}
      description="Add the registry endpoint and optional OCI credentials."
      dismissible={!isPending}
      footer={footer}
      headerMeta={
        <span className="status-pill status-pill-neutral">{tenantId ? `Tenant ${tenantId}` : 'No tenant selected'}</span>
      }
      initialFocusRef={initialFocusRef}
      onClose={onClose}
      open={open}
      size="wide"
      steps={wizardSteps}
      title="Create upstream"
    >
      <form className="upstreams-form upstreams-modal-form" id="create-upstream-form" onSubmit={onSubmit}>
        {isError ? (
          <div className="upstreams-feedback upstreams-feedback-error" role="alert">
            <strong>Unable to create upstream</strong>
            <p>{createErrorMessage}</p>
          </div>
        ) : null}

        {activeStep.id === 'connection' ? (
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
                placeholder={upstreamNameExamples[draft.ecosystem]}
                ref={initialFocusRef}
                value={draft.name}
              />
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
              {draftErrors.baseUrl ? (
                <p className="upstreams-field-error">{draftErrors.baseUrl}</p>
              ) : null}
            </div>

            <fieldset className="upstreams-capability-group">
              <legend>Capability profile</legend>
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
                      </span>
                    </label>
                  )
                })}
              </div>
            </fieldset>
          </div>
        ) : isAuthStep ? (
          <div className="upstreams-wizard-section">
            <div className="upstreams-wizard-copy">
              <h3>Authentication</h3>
            </div>

            <div className={`upstreams-field upstreams-auth-type-field${draftErrors.authType ? ' upstreams-field-invalid' : ''}`}>
              <label htmlFor="upstream-auth-type">Registry authentication</label>
              <select
                aria-invalid={Boolean(draftErrors.authType)}
                id="upstream-auth-type"
                name="authType"
                onChange={(event) => onDraftChange('authType', event.target.value)}
                value={draft.authType}
              >
                {authTypeOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              {draftErrors.authType ? <p className="upstreams-field-error">{draftErrors.authType}</p> : null}
            </div>

            {draft.authType === 'basic' ? (
              <div className="upstreams-auth-detail-fields">
                <div className={`upstreams-field${draftErrors.authUsername ? ' upstreams-field-invalid' : ''}`}>
                  <label htmlFor="upstream-auth-username">Username</label>
                  <input
                    aria-invalid={Boolean(draftErrors.authUsername)}
                    autoComplete="username"
                    id="upstream-auth-username"
                    name="authUsername"
                    onChange={(event) => onDraftChange('authUsername', event.target.value)}
                    value={draft.authUsername}
                  />
                  {draftErrors.authUsername ? (
                    <p className="upstreams-field-error">{draftErrors.authUsername}</p>
                  ) : null}
                </div>

                <div className={`upstreams-field${draftErrors.authPassword ? ' upstreams-field-invalid' : ''}`}>
                  <label htmlFor="upstream-auth-password">Password or PAT</label>
                  <input
                    aria-invalid={Boolean(draftErrors.authPassword)}
                    autoComplete="new-password"
                    id="upstream-auth-password"
                    name="authPassword"
                    onChange={(event) => onDraftChange('authPassword', event.target.value)}
                    type="password"
                    value={draft.authPassword}
                  />
                  {draftErrors.authPassword ? (
                    <p className="upstreams-field-error">{draftErrors.authPassword}</p>
                  ) : null}
                </div>
              </div>
            ) : null}

            {draft.authType === 'bearer_token' ? (
              <div className="upstreams-auth-detail-fields">
                <div className={`upstreams-field${draftErrors.authToken ? ' upstreams-field-invalid' : ''}`}>
                  <label htmlFor="upstream-auth-token">Bearer token</label>
                  <input
                    aria-invalid={Boolean(draftErrors.authToken)}
                    autoComplete="off"
                    id="upstream-auth-token"
                    name="authToken"
                    onChange={(event) => onDraftChange('authToken', event.target.value)}
                    type="password"
                    value={draft.authToken}
                  />
                  {draftErrors.authToken ? <p className="upstreams-field-error">{draftErrors.authToken}</p> : null}
                </div>
              </div>
            ) : null}
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
                <div>
                  <dt>Authentication</dt>
                  <dd>{formatDraftAuth(draft)}</dd>
                </div>
              </dl>
            </div>
          </div>
        )}
      </form>
    </ModalWizard>
  )
}
