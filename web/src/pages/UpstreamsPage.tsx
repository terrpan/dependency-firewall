import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ModalWizard, type ModalWizardStep } from '../components/modal/index.ts'
import { useNotifications } from '../features/notifications/useNotifications.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { useTenantControlPlaneApi } from '../features/tenant/useTenantControlPlaneApi.ts'
import {
  createEmptyUpstreamDraft,
  createUpstream,
  formatUpstreamCapabilityLabel,
  formatUpstreamTimestamp,
  getUpstreamCapabilityDefinitions,
  listUpstreams,
  listSupportedPolicyTypes,
  sortUpstreams,
  upstreamBaseUrlExamples,
  upstreamEcosystems,
  upstreamsQueryKey,
  validateUpstreamDraft,
  type UpstreamDraft,
  type UpstreamEcosystem,
} from '../features/upstreams/api.ts'
import '../features/upstreams/upstreams.css'
import { firewallRootUrl, joinUrlPath } from '../lib/config.ts'
import type { Upstream } from '../lib/api/types.ts'

function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message
  }

  return fallback
}

function formatPolicyTypeName(value: string): string {
  return value.replaceAll('_', ' ')
}

const createWizardSteps = [
  {
    id: 'connection',
    label: 'Connection',
    description: 'Choose the ecosystem, display name, and upstream URL.',
  },
  {
    id: 'review',
    label: 'Review',
    description: 'Confirm the tenant-scoped details before creating the upstream.',
  },
] satisfies readonly ModalWizardStep[]

type UpstreamsPageContentProps = {
  tenantId: string | null
}

function UpstreamsPageContent({ tenantId }: UpstreamsPageContentProps) {
  const api = useTenantControlPlaneApi()
  const { notifyError, notifySuccess } = useNotifications()
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState<UpstreamDraft>(() => createEmptyUpstreamDraft())
  const [draftErrors, setDraftErrors] = useState<Record<string, string>>({})
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const [createStep, setCreateStep] = useState(0)
  const [copiedUsageKey, setCopiedUsageKey] = useState<string | null>(null)
  const [copyErrorMessage, setCopyErrorMessage] = useState<string | null>(null)
  const nameInputRef = useRef<HTMLInputElement>(null)
  const copyResetTimerRef = useRef<number | null>(null)

  const upstreamsQuery = useQuery({
    queryKey: upstreamsQueryKey(tenantId),
    queryFn: ({ signal }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before loading upstreams.')
      }

      return listUpstreams(api, tenantId, signal)
    },
    enabled: Boolean(tenantId),
  })

  const upstreams = useMemo(() => sortUpstreams(upstreamsQuery.data ?? []), [upstreamsQuery.data])
  const selectedUpstreamId = searchParams.get('upstream')
  const selectedUpstream = useMemo(
    () => upstreams.find((upstream) => upstream.id === selectedUpstreamId) ?? upstreams[0] ?? null,
    [selectedUpstreamId, upstreams],
  )
  const selectedUpstreamUsage = useMemo(() => {
    if (!selectedUpstream) {
      return null
    }

    const firewallURL = new URL(firewallRootUrl)

    if (selectedUpstream.ecosystem === 'npm') {
      const registryUrl = joinUrlPath(
        firewallRootUrl,
        `/npm/t/${tenantId ?? '<tenant-id>'}/u/${selectedUpstream.id}/`,
      )
      return {
        title: 'Use with npm',
        summary: 'Point npm at this upstream-specific firewall route so installs resolve through the selected upstream.',
        primaryLabel: '.npmrc',
        primaryCode: `registry=${registryUrl}`,
        secondaryLabel: 'Install command',
        secondaryCode: `npm install lodash --registry ${registryUrl}`,
        note: tenantId
          ? `This route is pinned to upstream ${selectedUpstream.id} under /npm/t/${tenantId}/u/${selectedUpstream.id}/.`
          : 'Select a tenant to render the upstream-specific npm route.',
      }
    }

    const firewallHost = firewallURL.host
    const upstreamHost = tenantId
      ? `u-${selectedUpstream.id}.${tenantId}.${firewallHost}`
      : `u-<upstream-id>.<tenant-id>.${firewallHost}`
    const mirrorOrigin = `${firewallURL.protocol}//${upstreamHost}`
    return {
      title: 'Use with Docker',
      summary: 'Pull through this upstream-specific firewall hostname so Docker traffic resolves to the selected OCI upstream.',
      primaryLabel: 'docker pull',
      primaryCode: `docker pull ${upstreamHost}/library/nginx:1.25.3`,
      secondaryLabel: 'Optional mirror config',
      secondaryCode: `{\n  "registry-mirrors": ["${mirrorOrigin}"],\n  "insecure-registries": ["${upstreamHost}"]\n}`,
      note: tenantId
        ? `This hostname is pinned to upstream ${selectedUpstream.id} as u-${selectedUpstream.id}.${tenantId}.${firewallHost}.`
        : 'Select a tenant to render the upstream-specific registry hostname.',
    }
  }, [selectedUpstream, tenantId])
  const selectedUpstreamCapabilities = useMemo(
    () =>
      selectedUpstream
        ? (selectedUpstream.capabilities ?? []).map((capability) => formatUpstreamCapabilityLabel(capability))
        : [],
    [selectedUpstream],
  )
  const selectedUpstreamPolicyTypes = useMemo(
    () => (selectedUpstream ? listSupportedPolicyTypes(selectedUpstream).map(formatPolicyTypeName) : []),
    [selectedUpstream],
  )

  const setSelectedUpstreamId = useCallback(
    (nextUpstreamId: string | null) => {
      setCopiedUsageKey(null)
      setCopyErrorMessage(null)
      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current)
          if (nextUpstreamId) {
            next.set('upstream', nextUpstreamId)
          } else {
            next.delete('upstream')
          }
          return next
        },
        { replace: true },
      )
    },
    [setSearchParams],
  )

  useEffect(() => {
    return () => {
      if (copyResetTimerRef.current !== null) {
        window.clearTimeout(copyResetTimerRef.current)
      }
    }
  }, [])

  const createMutation = useMutation({
    mutationFn: async (nextDraft: UpstreamDraft) => {
      if (!tenantId) {
        throw new Error('Select a tenant before creating an upstream.')
      }

      const validation = validateUpstreamDraft(nextDraft)
      if (!validation.value) {
        throw new Error('Please fix the validation errors and try again.')
      }

      return createUpstream(api, tenantId, validation.value)
    },
    onSuccess: async (createdUpstream) => {
      queryClient.setQueryData<Upstream[]>(upstreamsQueryKey(tenantId), (current) =>
        sortUpstreams(
          [...(current ?? []), createdUpstream].filter(
            (upstream, index, items) => items.findIndex((item) => item.id === upstream.id) === index,
          ),
        ),
      )
      await queryClient.invalidateQueries({ queryKey: upstreamsQueryKey(tenantId) })
      setSelectedUpstreamId(createdUpstream.id)
      setDraft(createEmptyUpstreamDraft(createdUpstream.ecosystem as UpstreamEcosystem))
      setDraftErrors({})
      notifySuccess('Upstream created', `${createdUpstream.name} is now configured for this tenant.`)
      setCreateStep(0)
      setIsCreateModalOpen(false)
    },
  })
  const deleteMutation = useMutation({
    mutationFn: async (upstream: Upstream) => {
      if (!tenantId) {
        throw new Error('Select a tenant before deleting an upstream.')
      }

      await api.upstreams.remove(upstream.id, { tenantId })
      return upstream
    },
    onSuccess: async (deletedUpstream) => {
      const remainingUpstreams = sortUpstreams(
        upstreams.filter((upstream) => upstream.id !== deletedUpstream.id),
      )

      queryClient.setQueryData<Upstream[]>(upstreamsQueryKey(tenantId), remainingUpstreams)
      await queryClient.invalidateQueries({ queryKey: upstreamsQueryKey(tenantId) })
      setSelectedUpstreamId(remainingUpstreams[0]?.id ?? null)
      notifySuccess('Upstream deleted', `${deletedUpstream.name} has been removed.`)
    },
    onError: (error) => {
      notifyError('Upstream not deleted', getErrorMessage(error, 'Unable to delete the selected upstream right now.'))
    },
  })

  const listErrorMessage = getErrorMessage(
    upstreamsQuery.error,
    'Unable to load upstreams right now.',
  )
  const createErrorMessage = getErrorMessage(createMutation.error, 'Unable to create the upstream with the current values.')

  const openCreateModal = useCallback(() => {
    createMutation.reset()
    setDraftErrors({})
    setCreateStep(0)
    setIsCreateModalOpen(true)
  }, [createMutation])

  const closeCreateModal = useCallback(() => {
    if (createMutation.isPending) {
      return
    }

    createMutation.reset()
    setDraftErrors({})
    setCreateStep(0)
    setIsCreateModalOpen(false)
  }, [createMutation])

  function handleDraftChange(field: keyof UpstreamDraft, value: string) {
    createMutation.reset()
    setDraft((currentDraft) => {
      if (field !== 'ecosystem') {
        return {
          ...currentDraft,
          [field]: value,
        }
      }

      const nextEcosystem = value as UpstreamEcosystem
      const currentBaseUrl = currentDraft.baseUrl.trim()
      const shouldUseExample =
        !currentBaseUrl || currentBaseUrl === upstreamBaseUrlExamples[currentDraft.ecosystem]

      return {
        ...currentDraft,
        ecosystem: nextEcosystem,
        baseUrl: shouldUseExample ? upstreamBaseUrlExamples[nextEcosystem] : currentDraft.baseUrl,
        capabilities: createEmptyUpstreamDraft(nextEcosystem).capabilities,
      }
    })
    setDraftErrors((currentErrors) => {
      if (!currentErrors[field]) {
        return currentErrors
      }

      const nextErrors = { ...currentErrors }
      delete nextErrors[field]
      return nextErrors
    })
  }

  function handleCapabilityToggle(capability: string, checked: boolean) {
    createMutation.reset()
    setDraft((currentDraft) => {
      const nextCapabilities = checked
        ? [...currentDraft.capabilities.filter((currentCapability) => currentCapability !== capability), capability]
        : currentDraft.capabilities.filter((currentCapability) => currentCapability !== capability)

      return {
        ...currentDraft,
        capabilities: nextCapabilities,
      }
    })
  }

  function handleDraftReset() {
    createMutation.reset()
    setDraft(createEmptyUpstreamDraft(draft.ecosystem))
    setDraftErrors({})
  }

  async function handleCopyUsage(code: string, key: string) {
    try {
      await navigator.clipboard.writeText(code)
      setCopyErrorMessage(null)
      setCopiedUsageKey(key)

      if (copyResetTimerRef.current !== null) {
        window.clearTimeout(copyResetTimerRef.current)
      }

      copyResetTimerRef.current = window.setTimeout(() => {
        setCopiedUsageKey(null)
        copyResetTimerRef.current = null
      }, 1600)
    } catch {
      setCopyErrorMessage('Unable to copy right now.')
    }
  }

  async function handleDeleteUpstream(upstream: Upstream) {
    const confirmed = window.confirm(`Delete upstream "${upstream.name}"?`)
    if (!confirmed) {
      return
    }

    await deleteMutation.mutateAsync(upstream)
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const validation = validateUpstreamDraft(draft)
    if (!validation.value) {
      setDraftErrors(validation.errors)
      return
    }

    setDraftErrors({})

    if (createStep === 0) {
      setCreateStep(1)
      return
    }

    createMutation.mutate(draft)
  }

  const createModalAside = (
    <div className="upstreams-wizard-aside">
      <section className="upstreams-wizard-card">
        <p className="eyebrow">Tenant scope</p>
        <h3>Active tenant</h3>
        <p className="muted">
          This upstream will be created only for <code>{tenantId ?? 'the selected tenant'}</code>.
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
            <dd>
              {draft.capabilities.length > 0
                ? draft.capabilities.map((capability) => formatUpstreamCapabilityLabel(capability)).join(', ')
                : 'None selected'}
            </dd>
          </div>
        </dl>
      </section>

      <section className="upstreams-wizard-card">
        <h3>What happens next</h3>
        <p className="muted">
          After create succeeds, the new upstream becomes selected in the detail panel.
        </p>
      </section>
    </div>
  )

  const createModalFooter = (
    <div className="upstreams-wizard-footer">
      <div className="upstreams-form-actions">
        <button
          className="upstreams-secondary-button"
          disabled={createMutation.isPending}
          onClick={closeCreateModal}
          type="button"
        >
          Cancel
        </button>
        <button
          className="upstreams-secondary-button"
          disabled={createMutation.isPending}
          onClick={handleDraftReset}
          type="button"
        >
          Reset
        </button>
      </div>

      <div className="upstreams-form-actions">
        {createStep > 0 ? (
          <button
            className="upstreams-secondary-button"
            disabled={createMutation.isPending}
            onClick={() => setCreateStep(0)}
            type="button"
          >
            Back
          </button>
        ) : null}

        {createStep === 0 ? (
          <button
            className="primary-button"
            disabled={!tenantId || createMutation.isPending}
            form="create-upstream-form"
            type="submit"
          >
            Review details
          </button>
        ) : (
          <button
            className="primary-button"
            disabled={createMutation.isPending || !tenantId}
            form="create-upstream-form"
            type="submit"
          >
            {createMutation.isPending ? 'Creating…' : 'Create upstream'}
          </button>
        )}
      </div>
    </div>
  )

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Registry configuration</p>
          <h2>Upstreams</h2>
          <p className="page-summary">Keep the list and detail view in place while new upstreams are added in a modal.</p>
        </div>
        <div className="upstreams-actions">
          <span className="status-pill">{upstreams.length} configured</span>
          <button className="primary-button" disabled={!tenantId || createMutation.isPending} onClick={openCreateModal} type="button">
            New upstream
          </button>
          <button
            className="upstreams-secondary-button"
            disabled={upstreamsQuery.isPending || createMutation.isPending || deleteMutation.isPending}
            onClick={() => void upstreamsQuery.refetch()}
            type="button"
          >
            Refresh
          </button>
        </div>
      </header>

      <div className="upstreams-layout">
        <section className="card upstreams-panel">
          <div className="upstreams-panel-header">
            <div>
              <h3>Configured upstreams</h3>
              <p>Registry endpoints for the active tenant.</p>
            </div>
            {upstreamsQuery.isPending ? <span className="status-pill">Loading</span> : null}
          </div>

          {upstreamsQuery.isError ? (
            <div className="upstreams-feedback upstreams-feedback-error" role="alert">
              <strong>Unable to load upstreams</strong>
              <p>{listErrorMessage}</p>
            </div>
          ) : null}

          {upstreamsQuery.isSuccess && upstreams.length === 0 ? (
            <div className="upstreams-empty-state">
              <h3>No upstreams configured yet</h3>
              <p className="muted">Create the first upstream without leaving this page context.</p>
              <div className="upstreams-form-actions">
                <button className="primary-button" disabled={!tenantId || createMutation.isPending} onClick={openCreateModal} type="button">
                  Create upstream
                </button>
              </div>
            </div>
          ) : null}

          {upstreams.length > 0 ? (
            <div className="upstreams-list" role="list" aria-label="Configured upstreams">
              {upstreams.map((upstream) => {
                const isActive = upstream.id === selectedUpstream?.id

                return (
                  <button
                    key={upstream.id}
                    className={`upstreams-list-item${isActive ? ' is-active' : ''}`}
                    onClick={() => setSelectedUpstreamId(upstream.id)}
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

        <div className="upstreams-stack">
          <section className="card upstreams-panel">
            <div className="upstreams-panel-header">
              <div>
                <h3>Upstream details</h3>
                <p>Inspect the selected registry endpoint.</p>
              </div>
              {selectedUpstream ? (
                <div className="upstreams-panel-actions">
                  <span className="upstreams-badge">{selectedUpstream.ecosystem}</span>
                  <button
                    className="upstreams-secondary-button upstreams-danger-button"
                    disabled={deleteMutation.isPending}
                    onClick={() => void handleDeleteUpstream(selectedUpstream)}
                    type="button"
                  >
                    {deleteMutation.isPending && deleteMutation.variables?.id === selectedUpstream.id
                      ? 'Deleting…'
                      : 'Delete upstream'}
                  </button>
                </div>
              ) : null}
            </div>

            {selectedUpstream ? (
              <dl className="upstreams-detail">
                <div>
                  <dt>Name</dt>
                  <dd>{selectedUpstream.name}</dd>
                </div>
                <div>
                  <dt>Identifier</dt>
                  <dd>
                    <code>{selectedUpstream.id}</code>
                  </dd>
                </div>
                <div>
                  <dt>Base URL</dt>
                  <dd>
                    <a className="inline-link" href={selectedUpstream.base_url} target="_blank" rel="noreferrer">
                      {selectedUpstream.base_url}
                    </a>
                  </dd>
                </div>
                <div>
                  <dt>Capabilities</dt>
                  <dd>{selectedUpstreamCapabilities.length > 0 ? selectedUpstreamCapabilities.join(', ') : 'None'}</dd>
                </div>
                <div>
                  <dt>Supported policies</dt>
                  <dd>{selectedUpstreamPolicyTypes.length > 0 ? selectedUpstreamPolicyTypes.join(', ') : 'None'}</dd>
                </div>
                <div>
                  <dt>Created</dt>
                  <dd>{formatUpstreamTimestamp(selectedUpstream.created_at)}</dd>
                </div>
                <div>
                  <dt>Updated</dt>
                  <dd>{formatUpstreamTimestamp(selectedUpstream.updated_at)}</dd>
                </div>
              </dl>
            ) : (
              <div className="upstreams-empty-state">
                <h3>No detail selected</h3>
                <p className="muted">Pick an upstream from the list, or create the first one in the modal flow.</p>
              </div>
            )}
          </section>

          <section className="card upstreams-panel">
            <div className="upstreams-panel-header">
              <div>
                <h3>{selectedUpstreamUsage?.title ?? 'Usage instructions'}</h3>
                <p>
                  {selectedUpstreamUsage?.summary ?? 'Select an upstream to see how developers should use it from npm or Docker.'}
                </p>
              </div>
            </div>

            {selectedUpstreamUsage ? (
              <div className="upstreams-usage-guide">
                <div className="upstreams-usage-section">
                  <div className="upstreams-usage-header">
                    <span className="upstreams-usage-label">{selectedUpstreamUsage.primaryLabel}</span>
                    <button
                      className="upstreams-copy-button"
                      onClick={() =>
                        void handleCopyUsage(
                          selectedUpstreamUsage.primaryCode,
                          `${selectedUpstream.id}:primary`,
                        )
                      }
                      type="button"
                    >
                      {copiedUsageKey === `${selectedUpstream.id}:primary` ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-block">{selectedUpstreamUsage.primaryCode}</pre>
                </div>

                <div className="upstreams-usage-section">
                  <div className="upstreams-usage-header">
                    <span className="upstreams-usage-label">{selectedUpstreamUsage.secondaryLabel}</span>
                    <button
                      className="upstreams-copy-button"
                      onClick={() =>
                        void handleCopyUsage(
                          selectedUpstreamUsage.secondaryCode,
                          `${selectedUpstream.id}:secondary`,
                        )
                      }
                      type="button"
                    >
                      {copiedUsageKey === `${selectedUpstream.id}:secondary` ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-block">{selectedUpstreamUsage.secondaryCode}</pre>
                </div>

                {copyErrorMessage ? (
                  <div className="upstreams-feedback upstreams-feedback-error" role="alert">
                    <p>{copyErrorMessage}</p>
                  </div>
                ) : null}

                <p className="muted">{selectedUpstreamUsage.note}</p>
              </div>
            ) : (
              <div className="upstreams-empty-state">
                <h3>No usage instructions yet</h3>
                <p className="muted">Pick an upstream first so the page can show npm or Docker guidance.</p>
              </div>
            )}
          </section>
        </div>
      </div>

      <ModalWizard
        aside={createModalAside}
        closeOnEscape={!createMutation.isPending}
        closeOnOverlayClick={!createMutation.isPending}
        currentStep={createStep}
        description="Create a new npm or OCI upstream without leaving the list and detail context."
        dismissible={!createMutation.isPending}
        footer={createModalFooter}
        headerMeta={
          <span className="status-pill status-pill-neutral">{tenantId ? `Tenant ${tenantId}` : 'No tenant selected'}</span>
        }
        initialFocusRef={nameInputRef}
        onClose={closeCreateModal}
        open={isCreateModalOpen}
        size="wide"
        steps={createWizardSteps}
        title="Create upstream"
      >
        <form className="upstreams-form upstreams-modal-form" id="create-upstream-form" onSubmit={handleSubmit}>
          {createMutation.isError ? (
            <div className="upstreams-feedback upstreams-feedback-error" role="alert">
              <strong>Unable to create upstream</strong>
              <p>{createErrorMessage}</p>
            </div>
          ) : null}

          {createStep === 0 ? (
            <div className="upstreams-wizard-section">
              <div className="upstreams-wizard-copy">
                <h3>Connection details</h3>
                <p className="muted">Use a short name and a concrete registry base URL.</p>
              </div>

              <div className={`upstreams-field${draftErrors.name ? ' upstreams-field-invalid' : ''}`}>
                <label htmlFor="upstream-name">Display name</label>
                <input
                  aria-invalid={Boolean(draftErrors.name)}
                  id="upstream-name"
                  name="name"
                  onChange={(event) => handleDraftChange('name', event.target.value)}
                  placeholder="docker-hub"
                  ref={nameInputRef}
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
                  onChange={(event) => handleDraftChange('ecosystem', event.target.value)}
                  value={draft.ecosystem}
                >
                  {upstreamEcosystems.map((ecosystem) => (
                    <option key={ecosystem} value={ecosystem}>
                      {ecosystem.toUpperCase()}
                    </option>
                  ))}
                </select>
                <small>Each tenant can register multiple upstreams per ecosystem. Duplicate registry URLs are blocked.</small>
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
                  onChange={(event) => handleDraftChange('baseUrl', event.target.value)}
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
                <p className="muted">
                  Capabilities decide which policy types can be scoped to this upstream.
                </p>
                <div className="upstreams-capability-list">
                  {getUpstreamCapabilityDefinitions(draft.ecosystem).map((capability) => {
                    const checked = draft.capabilities.includes(capability.id)
                    return (
                      <label key={capability.id} className="upstreams-capability-option">
                        <input
                          checked={checked}
                          onChange={(event) => handleCapabilityToggle(capability.id, event.target.checked)}
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
                <p className="muted">Confirm the upstream details before creating it for this tenant.</p>
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
                    <dd>
                      {draft.capabilities.length > 0
                        ? draft.capabilities.map((capability) => formatUpstreamCapabilityLabel(capability)).join(', ')
                        : 'None selected'}
                    </dd>
                  </div>
                </dl>
              </div>
            </div>
          )}
        </form>
      </ModalWizard>
    </section>
  )
}

export function UpstreamsPage() {
  const { tenantId } = useTenant()

  return <UpstreamsPageContent key={tenantId ?? 'no-tenant'} tenantId={tenantId} />
}
