// PolicyDraftModal renders the guided create/edit policy workflow.
import { ModalWizard } from '../../components/modal/index.ts'
import type { DependencyScope, DependencyType, PolicyType, PolicyTypeDescriptor, Upstream } from '../../lib/api/index.ts'
import {
  getPolicyTypeLabel,
  getSupportedActions,
  type PolicyDraftState,
} from './draft.ts'
import type { DraftDefinition } from './draftDefinitions.ts'
import { formatUpstreamOptionLabel, getActionTone } from './display.ts'
import { policyWizardSteps, type PolicyDraftFieldErrorKey, type PreviewFormat } from './policyDraftWizard.ts'
import { formatUpstreamCapabilityLabel } from '../upstreams/api.ts'

type DraftFieldErrors = Partial<Record<PolicyDraftFieldErrorKey, string>>

type PolicyDraftModalProps = {
  open: boolean
  tenantId: string | null
  isEditingPolicy: boolean
  hasCreateDraftInProgress: boolean
  currentStep: number
  draft: PolicyDraftState
  normalizedDraft: PolicyDraftState
  draftFieldErrors: DraftFieldErrors
  previewFormat: PreviewFormat
  jsonPreview: string
  yamlPreview: string
  upstreams: readonly Upstream[]
  upstreamsIsPending: boolean
  upstreamsIsError: boolean
  upstreamsErrorMessage: string | null
  selectedUpstream: Upstream | null
  selectedDescriptor: PolicyTypeDescriptor | null
  selectedDefinition: DraftDefinition | null
  compatiblePolicyTypesByUpstream: Map<string, readonly PolicyTypeDescriptor[]>
  compatiblePolicyTypes: readonly PolicyTypeDescriptor[]
  supportedDraftActions: readonly PolicyDraftState['action'][]
  supportsLicenseAllowlistMissingBehavior: boolean
  supportsScorecardUnavailableBehavior: boolean
  reviewErrors: readonly string[]
  savePolicyIsPending: boolean
  savePolicyIsError: boolean
  savePolicyErrorMessage: string | null
  policyTypesIsError: boolean
  canAdvanceWizard: boolean
  onClose: () => void
  onStepChange: (step: number) => void
  onPreviewFormatChange: (format: PreviewFormat) => void
  onBack: () => void
  onResetDraft: () => void
  onSavePolicy: () => void
  onNext: () => void
  onUpstreamSelect: (upstreamId: string) => void
  onTypeSelect: (type: PolicyType) => void
  onDraftChange: <K extends keyof PolicyDraftState>(key: K, value: PolicyDraftState[K]) => void
}

function getSchemaVersions(descriptor: PolicyTypeDescriptor) {
  return descriptor.supported_schema_versions?.length
    ? descriptor.supported_schema_versions
    : [descriptor.current_schema_version]
}

function getRequiredCapabilities(descriptor: PolicyTypeDescriptor): string[] {
  return descriptor.required_capabilities ?? []
}

function getPolicyEffectCopy(
  descriptor: PolicyTypeDescriptor | null,
  definition: DraftDefinition | null,
): { summary: string; description: string | null } | null {
  if (!descriptor || !definition) {
    return null
  }

  const summary = descriptor.summary || definition.summary
  const description = descriptor.description || definition.description

  return {
    summary,
    description: description && description !== summary ? description : null,
  }
}

const dependencyScopeOptions: { value: DependencyScope; label: string }[] = [
  { value: 'direct', label: 'Direct' },
  { value: 'transitive', label: 'Transitive' },
  { value: 'unknown', label: 'Unknown context' },
]

const dependencyTypeOptions: { value: DependencyType; label: string }[] = [
  { value: 'prod', label: 'Production' },
  { value: 'dev', label: 'Development' },
  { value: 'peer', label: 'Peer' },
  { value: 'optional', label: 'Optional' },
]

function toggleValue<T extends string>(values: readonly T[], value: T, checked: boolean): T[] {
  if (checked) {
    return values.includes(value) ? [...values] : [...values, value]
  }

  return values.filter((item) => item !== value)
}

export function PolicyDraftModal({
  open,
  isEditingPolicy,
  hasCreateDraftInProgress,
  currentStep,
  draft,
  normalizedDraft,
  draftFieldErrors,
  previewFormat,
  jsonPreview,
  yamlPreview,
  upstreams,
  upstreamsIsPending,
  upstreamsIsError,
  upstreamsErrorMessage,
  selectedUpstream,
  selectedDescriptor,
  selectedDefinition,
  compatiblePolicyTypesByUpstream,
  compatiblePolicyTypes,
  supportedDraftActions,
  supportsLicenseAllowlistMissingBehavior,
  supportsScorecardUnavailableBehavior,
  reviewErrors,
  savePolicyIsPending,
  savePolicyIsError,
  savePolicyErrorMessage,
  policyTypesIsError,
  canAdvanceWizard,
  onClose,
  onStepChange,
  onPreviewFormatChange,
  onBack,
  onResetDraft,
  onSavePolicy,
  onNext,
  onUpstreamSelect,
  onTypeSelect,
  onDraftChange,
}: PolicyDraftModalProps) {
  const currentPolicyWizardStep = policyWizardSteps[currentStep] ?? null
  const policyEffectCopy = getPolicyEffectCopy(selectedDescriptor, selectedDefinition)
  const previewAside =
    currentStep >= 2 ? (
      <div className="policy-preview-column">
        <section className="policy-preview-card policy-preview-card-compact">
          <div className="policy-preview-header">
            <h4>Preview</h4>
            <div className="policy-preview-toggle" aria-label="Policy preview format">
              <button
                aria-pressed={previewFormat === 'json'}
                className={`policy-preview-toggle-button${previewFormat === 'json' ? ' active' : ''}`}
                onClick={() => onPreviewFormatChange('json')}
                type="button"
              >
                JSON
              </button>
              <button
                aria-pressed={previewFormat === 'yaml'}
                className={`policy-preview-toggle-button${previewFormat === 'yaml' ? ' active' : ''}`}
                onClick={() => onPreviewFormatChange('yaml')}
                type="button"
              >
                YAML
              </button>
            </div>
          </div>
          <pre className="code-block policy-preview-block">{previewFormat === 'json' ? jsonPreview : yamlPreview}</pre>
        </section>
      </div>
    ) : undefined

  return (
    <ModalWizard
      allowStepSelection
      aside={previewAside}
      currentStep={currentStep}
      description={isEditingPolicy ? 'Edit the selected policy.' : 'Create a tenant-scoped policy.'}
      dismissible={!savePolicyIsPending}
      footer={
        <div className="wizard-actions wizard-actions-modal">
          <button className="secondary-button" disabled={currentStep === 0} onClick={onBack} type="button">
            Back
          </button>
          <div className="wizard-actions-right">
            <button className="secondary-button" onClick={onResetDraft} type="button">
              {isEditingPolicy ? 'Reset changes' : 'Discard draft'}
            </button>
            {currentStep === policyWizardSteps.length - 1 ? (
              <button
                className="primary-button"
                disabled={reviewErrors.length > 0 || savePolicyIsPending}
                onClick={onSavePolicy}
                type="button"
              >
                {savePolicyIsPending
                  ? isEditingPolicy
                    ? 'Saving changes...'
                    : 'Creating policy...'
                  : isEditingPolicy
                    ? 'Save changes'
                    : 'Create policy'}
              </button>
            ) : (
              <button className="primary-button" disabled={!canAdvanceWizard} onClick={onNext} type="button">
                Next
              </button>
            )}
          </div>
        </div>
      }
      headerMeta={
        <>
          {isEditingPolicy ? <span className="status-pill status-pill-neutral">Editing</span> : null}
          {draft.type ? <span className="policy-badge policy-badge-info">{draft.type}</span> : null}
          {policyTypesIsError ? (
            <span className="status-pill status-pill-neutral">Fallback metadata</span>
          ) : null}
        </>
      }
      onClose={onClose}
      onStepChange={onStepChange}
      open={open}
      showStepDescriptions={false}
      size="full"
      stepGuideVariant="compact"
      steps={policyWizardSteps}
      title={isEditingPolicy ? 'Edit policy' : hasCreateDraftInProgress ? 'Create policy draft' : 'Create policy'}
    >
      <div className="policy-wizard-main">
        <div className="policy-modal-copy">
          <div className="policy-section-heading">
            <div>
              <h3>{currentPolicyWizardStep?.label}</h3>
              {currentPolicyWizardStep?.description ? (
                <p className="muted">{currentPolicyWizardStep.description}</p>
              ) : null}
            </div>
          </div>
        </div>

        {currentStep === 0 ? (
          <div className="policy-form-stack">
            {draftFieldErrors.upstreamId ? (
              <section className="policy-error-panel">
                <h4>Choose an upstream to continue</h4>
                <p className="muted">{draftFieldErrors.upstreamId}</p>
              </section>
            ) : null}

            {upstreams.length > 0 ? (
              <div className="policy-type-grid">
                {upstreams.map((upstream) => {
                  const isSelected = upstream.id === normalizedDraft.upstreamId.trim()
                  const compatibleDescriptorsForUpstream = compatiblePolicyTypesByUpstream.get(upstream.id) ?? []

                  return (
                    <button
                      key={upstream.id}
                      className={`policy-type-card${isSelected ? ' selected' : ''}`}
                      onClick={() => onUpstreamSelect(upstream.id)}
                      type="button"
                    >
                      <div className="policy-type-card-header">
                        <strong>{upstream.name}</strong>
                        <span className="policy-badge policy-badge-info">{upstream.ecosystem.toUpperCase()}</span>
                      </div>
                      <p className="muted">{upstream.base_url}</p>
                      <div className="policy-chip-row">
                        <span className="policy-chip">
                          {compatibleDescriptorsForUpstream.length} policy type
                          {compatibleDescriptorsForUpstream.length === 1 ? '' : 's'}
                        </span>
                        {(upstream.capabilities ?? []).map((capability) => (
                          <span key={capability} className="policy-chip">
                            {formatUpstreamCapabilityLabel(capability)}
                          </span>
                        ))}
                        {upstream.capabilities?.length ? null : (
                          <span className="policy-chip">Base compatibility only</span>
                        )}
                      </div>
                    </button>
                  )
                })}
              </div>
            ) : null}

            {upstreamsIsError ? (
              <section className="policy-error-panel">
                <h4>Unable to load upstreams</h4>
                <p className="muted">{upstreamsErrorMessage}</p>
              </section>
            ) : null}

            {!upstreamsIsPending && upstreams.length === 0 ? (
              <section className="policy-summary-card">
                <h4>Create an upstream first</h4>
                <p className="muted">
                  Policies are scoped to an upstream in the firewall, so add an npm or OCI upstream before creating
                  this rule.
                </p>
              </section>
            ) : null}
          </div>
        ) : null}

        {currentStep === 1 ? (
          <div className="policy-form-stack">
            {selectedUpstream ? (
              <section className="policy-summary-card policy-summary-card-compact">
                <h4>{selectedUpstream.name}</h4>
                <div className="policy-chip-row">
                  <span className="policy-chip">{selectedUpstream.base_url}</span>
                  {(selectedUpstream.capabilities ?? []).map((capability) => (
                    <span key={capability} className="policy-chip">
                      {formatUpstreamCapabilityLabel(capability)}
                    </span>
                  ))}
                  {selectedUpstream.capabilities?.length ? null : (
                    <span className="policy-chip">Base compatibility only</span>
                  )}
                </div>
              </section>
            ) : null}

            {draftFieldErrors.type ? (
              <section className="policy-error-panel">
                <h4>Choose a policy type to continue</h4>
                <p className="muted">{draftFieldErrors.type}</p>
              </section>
            ) : null}

            {selectedUpstream && compatiblePolicyTypes.length > 0 ? (
              <div className="policy-type-grid">
                {compatiblePolicyTypes.map((descriptor) => {
                  const descriptorType = descriptor.type as PolicyType
                  const isSelected = descriptorType === draft.type
                  const supportedActions = getSupportedActions(descriptorType, descriptor)

                  return (
                    <button
                      key={descriptor.type}
                      className={`policy-type-card${isSelected ? ' selected' : ''}`}
                      onClick={() => onTypeSelect(descriptorType)}
                      type="button"
                    >
                      <div className="policy-type-card-header">
                        <strong>{getPolicyTypeLabel(descriptorType)}</strong>
                        <span className="policy-badge policy-badge-info">{descriptor.type}</span>
                      </div>
                      <p className="muted">{descriptor.summary}</p>
                      <div className="policy-chip-row">
                        {supportedActions.map((action) => (
                          <span key={action} className="policy-chip">
                            {action}
                          </span>
                        ))}
                        {getSchemaVersions(descriptor).map((version) => (
                          <span key={version} className="policy-chip">
                            schema v{version}
                          </span>
                        ))}
                        {getRequiredCapabilities(descriptor).map((capability) => (
                          <span key={capability} className="policy-chip">
                            {formatUpstreamCapabilityLabel(capability)}
                          </span>
                        ))}
                      </div>
                    </button>
                  )
                })}
              </div>
            ) : null}

            {selectedUpstream && compatiblePolicyTypes.length === 0 ? (
              <section className="policy-summary-card">
                <h4>No compatible policy types yet</h4>
                <p className="muted">
                  Update this upstream's capability profile or choose another upstream before creating a policy.
                </p>
              </section>
            ) : null}
          </div>
        ) : null}

        {currentStep === 2 && draft.type && selectedDescriptor && selectedDefinition && selectedUpstream ? (
          <div className="policy-form-grid">
            {policyEffectCopy ? (
              <section className="policy-summary-card policy-effect-card">
                <h4>{getPolicyTypeLabel(draft.type)}</h4>
                <p className="muted">{policyEffectCopy.summary}</p>
                {policyEffectCopy.description ? <p className="muted">{policyEffectCopy.description}</p> : null}
              </section>
            ) : null}

            <label className="policy-field">
              <span>Upstream scope</span>
              <div className="policy-readonly-value">
                {formatUpstreamOptionLabel(selectedUpstream)}
                <code>{selectedUpstream.id}</code>
              </div>
            </label>

            <label className="policy-field">
              <span>Policy type</span>
              <div className="policy-readonly-value">
                {getPolicyTypeLabel(draft.type)}
                <code>{draft.type}</code>
              </div>
            </label>

            <label className={`policy-field${draftFieldErrors.name ? ' policy-field-invalid' : ''}`}>
              <span>Policy name</span>
              <input
                aria-invalid={Boolean(draftFieldErrors.name)}
                onChange={(event) => onDraftChange('name', event.target.value)}
                placeholder="block-outdated-packages"
                type="text"
                value={draft.name}
              />
              {draftFieldErrors.name ? <p className="policy-field-error">{draftFieldErrors.name}</p> : null}
            </label>

            <label className="policy-field">
              <span>Action</span>
              <select
                disabled={supportedDraftActions.length === 1}
                onChange={(event) => onDraftChange('action', event.target.value as PolicyDraftState['action'])}
                value={normalizedDraft.action}
              >
                {supportedDraftActions.map((action) => (
                  <option key={action} value={action}>
                    {action}
                  </option>
                ))}
              </select>
            </label>

            <label className={`policy-field${draftFieldErrors.priority ? ' policy-field-invalid' : ''}`}>
              <span>Priority</span>
              <input
                aria-invalid={Boolean(draftFieldErrors.priority)}
                onChange={(event) => onDraftChange('priority', event.target.value)}
                placeholder={String(selectedDefinition.defaultPriority)}
                step="1"
                type="number"
                value={draft.priority}
              />
              {draftFieldErrors.priority ? (
                <p className="policy-field-error">{draftFieldErrors.priority}</p>
              ) : null}
            </label>

            <label className={`policy-field${draftFieldErrors.schemaVersion ? ' policy-field-invalid' : ''}`}>
              <span>Schema version</span>
              <select
                aria-invalid={Boolean(draftFieldErrors.schemaVersion)}
                onChange={(event) => onDraftChange('schemaVersion', event.target.value)}
                value={draft.schemaVersion}
              >
                {getSchemaVersions(selectedDescriptor).map((version) => (
                  <option key={version} value={String(version)}>
                    Schema v{version}
                  </option>
                ))}
              </select>
              {draftFieldErrors.schemaVersion ? (
                <p className="policy-field-error">{draftFieldErrors.schemaVersion}</p>
              ) : null}
            </label>

            <label className="policy-field checkbox-field">
              <input
                checked={draft.enabled}
                onChange={(event) => onDraftChange('enabled', event.target.checked)}
                type="checkbox"
              />
              <span>Policy is enabled</span>
            </label>
          </div>
        ) : null}

        {currentStep === 3 && draft.type && selectedUpstream ? (
          <div className="policy-form-stack">
            <section className="policy-summary-card policy-effect-card">
              <h4>Dependency target</h4>
              <p className="muted">
                Targeting is available for npm policies. When enabled, graph context is resolved asynchronously and unknown context follows the selected fallback.
              </p>
            </section>

            {selectedUpstream.ecosystem === 'npm' ? (
              <>
                <label className="policy-field checkbox-field">
                  <input
                    checked={draft.targetEnabled}
                    onChange={(event) => onDraftChange('targetEnabled', event.target.checked)}
                    type="checkbox"
                  />
                  <span>Apply this policy only for selected dependency context</span>
                </label>

                {draft.targetEnabled ? (
                  <>
                    <div className="policy-form-grid">
                      <fieldset className="policy-field">
                        <span>Dependency scope</span>
                        {dependencyScopeOptions.map((option) => (
                          <label key={option.value} className="checkbox-field">
                            <input
                              checked={draft.targetDependencyScopes.includes(option.value)}
                              onChange={(event) =>
                                onDraftChange(
                                  'targetDependencyScopes',
                                  toggleValue(draft.targetDependencyScopes, option.value, event.target.checked),
                                )
                              }
                              type="checkbox"
                            />
                            <span>{option.label}</span>
                          </label>
                        ))}
                        <small>Leave all unchecked to match any dependency scope. Select unknown context to target unresolved graph evidence explicitly.</small>
                      </fieldset>

                      <fieldset className="policy-field">
                        <span>Dependency type</span>
                        {dependencyTypeOptions.map((option) => (
                          <label key={option.value} className="checkbox-field">
                            <input
                              checked={draft.targetDependencyTypes.includes(option.value)}
                              onChange={(event) =>
                                onDraftChange(
                                  'targetDependencyTypes',
                                  toggleValue(draft.targetDependencyTypes, option.value, event.target.checked),
                                )
                              }
                              type="checkbox"
                            />
                            <span>{option.label}</span>
                          </label>
                        ))}
                        <small>Leave all unchecked to match any dependency type once context is known.</small>
                      </fieldset>
                    </div>

                    <label className="policy-field">
                      <span>When graph context is unknown</span>
                      <select
                        onChange={(event) =>
                          onDraftChange(
                            'targetOnUnknown',
                            event.target.value as PolicyDraftState['targetOnUnknown'],
                          )
                        }
                        value={draft.targetOnUnknown}
                      >
                        <option value="warn">Warn only</option>
                        <option value="deny">Evaluate normally</option>
                        <option value="skip">Skip this policy</option>
                      </select>
                      <small>Unknown is used before async graph resolution completes or when graph evidence conflicts.</small>
                    </label>
                  </>
                ) : null}
              </>
            ) : (
              <section className="policy-summary-card">
                <h4>Not available for this upstream</h4>
                <p className="muted">Dependency graph targeting is currently npm-only.</p>
              </section>
            )}
          </div>
        ) : null}

        {currentStep === 4 && draft.type && selectedDescriptor && selectedDefinition ? (
          <div className="policy-form-stack">
            {policyEffectCopy ? (
              <section className="policy-summary-card policy-effect-card">
                <h4>{getPolicyTypeLabel(draft.type)}</h4>
                <p className="muted">{policyEffectCopy.summary}</p>
              </section>
            ) : null}

            {draft.type === 'cvss_threshold' ? (
              <div className="policy-form-grid">
                <label
                  className={`policy-field policy-threshold-option${draft.useCVSSThreshold ? ' policy-threshold-option-active' : ''}${draftFieldErrors.numericValue ? ' policy-field-invalid' : ''}`}
                >
                  <span className="policy-threshold-toggle-label">
                    <input
                      checked={draft.useCVSSThreshold}
                      onChange={(event) => {
                        const checked = event.target.checked
                        const nextNumericValue =
                          checked && !draft.numericValue.trim() && selectedDefinition.numberDefault !== undefined
                            ? String(selectedDefinition.numberDefault)
                            : draft.numericValue
                        onDraftChange('useCVSSThreshold', checked)
                        onDraftChange('numericValue', nextNumericValue)
                      }}
                      type="checkbox"
                    />
                    <span>Use CVSS score threshold</span>
                  </span>
                  <input
                    aria-invalid={Boolean(draftFieldErrors.numericValue)}
                    disabled={!draft.useCVSSThreshold}
                    min={selectedDefinition.numberMin}
                    onChange={(event) => onDraftChange('numericValue', event.target.value)}
                    placeholder={
                      selectedDefinition.numberDefault === undefined ? '' : String(selectedDefinition.numberDefault)
                    }
                    step={selectedDefinition.numberStep}
                    type="number"
                    value={draft.numericValue}
                  />
                  <small>Enable this to deny artifacts at or above the CVSS score threshold.</small>
                  {draftFieldErrors.numericValue ? (
                    <p className="policy-field-error">{draftFieldErrors.numericValue}</p>
                  ) : null}
                </label>

                <label
                  className={`policy-field policy-threshold-option${draft.useMinimumSeverity ? ' policy-threshold-option-active' : ''}${draftFieldErrors.minimumSeverity ? ' policy-field-invalid' : ''}`}
                >
                  <span className="policy-threshold-toggle-label">
                    <input
                      checked={draft.useMinimumSeverity}
                      onChange={(event) => {
                        const checked = event.target.checked
                        const nextMinimumSeverity =
                          checked && !draft.minimumSeverity ? 'high' : draft.minimumSeverity
                        onDraftChange('useMinimumSeverity', checked)
                        onDraftChange('minimumSeverity', nextMinimumSeverity)
                      }}
                      type="checkbox"
                    />
                    <span>Use minimum severity threshold</span>
                  </span>
                  <select
                    aria-invalid={Boolean(draftFieldErrors.minimumSeverity)}
                    disabled={!draft.useMinimumSeverity}
                    onChange={(event) =>
                      onDraftChange(
                        'minimumSeverity',
                        event.target.value as PolicyDraftState['minimumSeverity'],
                      )
                    }
                    value={draft.minimumSeverity}
                  >
                    <option value="">Not set</option>
                    <option value="none">None</option>
                    <option value="low">Low</option>
                    <option value="medium">Moderate</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                  <small>Enable this to deny artifacts with vulnerabilities at or above this severity.</small>
                  {draftFieldErrors.minimumSeverity ? (
                    <p className="policy-field-error">{draftFieldErrors.minimumSeverity}</p>
                  ) : null}
                </label>
              </div>
            ) : selectedDefinition.numberField ? (
              <label className={`policy-field${draftFieldErrors.numericValue ? ' policy-field-invalid' : ''}`}>
                <span>{selectedDefinition.numberLabel}</span>
                <input
                  aria-invalid={Boolean(draftFieldErrors.numericValue)}
                  min={selectedDefinition.numberMin}
                  onChange={(event) => onDraftChange('numericValue', event.target.value)}
                  placeholder={
                    selectedDefinition.numberDefault === undefined ? '' : String(selectedDefinition.numberDefault)
                  }
                  step={selectedDefinition.numberStep}
                  type="number"
                  value={draft.numericValue}
                />
                {draft.type === 'scorecard' ? (
                  <small>Uses the top-level Scorecard <code>score</code>. Leave blank if you only want named check thresholds.</small>
                ) : null}
                {draftFieldErrors.numericValue ? (
                  <p className="policy-field-error">{draftFieldErrors.numericValue}</p>
                ) : null}
              </label>
            ) : null}

            {selectedDefinition.listField ? (
              <label className={`policy-field${draftFieldErrors.listValue ? ' policy-field-invalid' : ''}`}>
                <span>{selectedDefinition.listLabel}</span>
                <textarea
                  aria-invalid={Boolean(draftFieldErrors.listValue)}
                  onChange={(event) => onDraftChange('listValue', event.target.value)}
                  placeholder={selectedDefinition.listPlaceholder}
                  rows={4}
                  value={draft.listValue}
                />
                <small>
                  {draft.type === 'scorecard'
                    ? 'Use one "check=score" or "check: score" entry per line with Scorecard check names like "branch-protection". Checks that report -1 follow the unavailable-data behavior.'
                    : 'Enter one value per line or separate items with commas.'}
                </small>
                {draftFieldErrors.listValue ? (
                  <p className="policy-field-error">{draftFieldErrors.listValue}</p>
                ) : null}
              </label>
            ) : null}

            {selectedDefinition.supportsExcludePackages ? (
              <label className="policy-field">
                <span>Exclude packages</span>
                <textarea
                  onChange={(event) => onDraftChange('excludePackages', event.target.value)}
                  placeholder="left-pad\n@scope/stable-lib"
                  rows={3}
                  value={draft.excludePackages}
                />
                <small>Optional package exceptions for age-based rules.</small>
              </label>
            ) : null}

            {supportsLicenseAllowlistMissingBehavior ? (
              <div className="policy-form-grid">
                <label className="policy-field">
                  <span>When no license is declared</span>
                  <select
                    onChange={(event) =>
                      onDraftChange(
                        'unlicensedBehavior',
                        event.target.value as PolicyDraftState['unlicensedBehavior'],
                      )
                    }
                    value={draft.unlicensedBehavior}
                  >
                    <option value="deny">Deny artifact</option>
                    <option value="skip">Skip this policy</option>
                  </select>
                  <small>Use deny to fail closed or skip to ignore artifacts that declare no license.</small>
                </label>

                <label className="policy-field">
                  <span>When license metadata is unavailable</span>
                  <select
                    onChange={(event) =>
                      onDraftChange(
                        'unavailableMetadataBehavior',
                        event.target.value as PolicyDraftState['unavailableMetadataBehavior'],
                      )
                    }
                    value={draft.unavailableMetadataBehavior}
                  >
                    <option value="deny">Deny artifact</option>
                    <option value="skip">Skip this policy</option>
                  </select>
                  <small>Use skip if unavailable enrichment should not deny on its own.</small>
                </label>
              </div>
            ) : null}

            {supportsScorecardUnavailableBehavior ? (
              <div className="policy-form-grid">
                <label className="policy-field">
                  <span>When Scorecard data is unavailable</span>
                  <select
                    onChange={(event) =>
                      onDraftChange(
                        'scorecardUnavailableBehavior',
                        event.target.value as PolicyDraftState['scorecardUnavailableBehavior'],
                      )
                    }
                    value={draft.scorecardUnavailableBehavior}
                  >
                    <option value="deny">Deny artifact</option>
                    <option value="skip">Skip this policy</option>
                  </select>
                  <small>Use skip if missing repository data, unavailable hosted Scorecard data, or checks that report -1 should not deny on their own.</small>
                </label>
              </div>
            ) : null}

            <label className="policy-field checkbox-field">
              <input
                checked={draft.dryRun}
                onChange={(event) => onDraftChange('dryRun', event.target.checked)}
                type="checkbox"
              />
              <span>Record matches as dry-run warnings instead of denying immediately</span>
            </label>

          </div>
        ) : null}

        {currentStep === 5 ? (
          <div className="policy-review-stack">
            <section className="policy-summary-card">
              <h4>Review before {isEditingPolicy ? 'saving' : 'creating'}</h4>
              {policyEffectCopy ? <p className="muted">{policyEffectCopy.summary}</p> : null}
              <div className="policy-chip-row">
                {selectedUpstream ? <span className="policy-chip">{formatUpstreamOptionLabel(selectedUpstream)}</span> : null}
                {draft.type ? <span className="policy-chip">{getPolicyTypeLabel(draft.type)}</span> : null}
                <span className={`policy-badge ${getActionTone(normalizedDraft.action)}`}>{normalizedDraft.action}</span>
              </div>
            </section>

            {reviewErrors.length > 0 ? (
              <section className="policy-error-panel">
                <h4>Complete these fields before saving the policy</h4>
                <ul className="list compact-list">
                  {reviewErrors.map((error) => (
                    <li key={error}>{error}</li>
                  ))}
                </ul>
              </section>
            ) : null}

            {savePolicyIsError ? (
              <section className="policy-error-panel">
                <h4>Unable to save policy</h4>
                <p className="muted">{savePolicyErrorMessage}</p>
              </section>
            ) : null}
          </div>
        ) : null}
      </div>
    </ModalWizard>
  )
}
