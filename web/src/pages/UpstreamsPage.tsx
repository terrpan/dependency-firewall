import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useNotifications } from '../features/notifications/useNotifications.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { useTenantControlPlaneApi } from '../features/tenant/useTenantControlPlaneApi.ts'
import {
  createEmptyUpstreamDraft,
  createUpstream,
  listUpstreams,
  sortUpstreams,
  upstreamEcosystemSupportsAuth,
  upstreamsQueryKey,
  validateUpstreamDraft,
  type UpstreamCapability,
  type UpstreamDraft,
  type UpstreamDraftErrors,
  type UpstreamEcosystem,
} from '../features/upstreams/api.ts'
import { CreateUpstreamModal } from '../features/upstreams/CreateUpstreamModal.tsx'
import { UpstreamDetailsPanel, UpstreamUsagePanel, UpstreamsListPanel } from '../features/upstreams/components.tsx'
import { toggleUpstreamDraftCapability, updateUpstreamDraftField } from '../features/upstreams/draft.ts'
import {
  formatUpstreamCapabilities,
  formatUpstreamPolicyTypes,
  formatUpstreamTimestamp,
} from '../features/upstreams/model.ts'
import { buildUpstreamUsageGuide } from '../features/upstreams/usage.ts'
import { upstreamClass } from '../features/upstreams/styles.ts'
import { firewallRootUrl } from '../lib/config.ts'
import type { Upstream } from '../lib/api/types.ts'
import { PageHeader } from '../ui/index.ts'

function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message
  }

  return fallback
}

type UpstreamsPageContentProps = {
  tenantId: string | null
  tenantName: string | null
}

function UpstreamsPageContent({ tenantId, tenantName }: UpstreamsPageContentProps) {
  const api = useTenantControlPlaneApi()
  const { notifyError, notifySuccess } = useNotifications()
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState<UpstreamDraft>(() => createEmptyUpstreamDraft())
  const [draftErrors, setDraftErrors] = useState<UpstreamDraftErrors>({})
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const [createStep, setCreateStep] = useState(0)
  const [copiedUsageKey, setCopiedUsageKey] = useState<string | null>(null)
  const [copyErrorMessage, setCopyErrorMessage] = useState<string | null>(null)
  const [deleteConfirmationId, setDeleteConfirmationId] = useState<string | null>(null)
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

    return buildUpstreamUsageGuide(selectedUpstream, tenantId, firewallRootUrl)
  }, [selectedUpstream, tenantId])
  const selectedUpstreamCapabilities = useMemo(() => formatUpstreamCapabilities(selectedUpstream), [selectedUpstream])
  const selectedUpstreamPolicyTypes = useMemo(() => formatUpstreamPolicyTypes(selectedUpstream), [selectedUpstream])
  const createStepCount = upstreamEcosystemSupportsAuth(draft.ecosystem) ? 3 : 2
  const createReviewStep = createStepCount - 1

  const setSelectedUpstreamId = useCallback(
    (nextUpstreamId: string | null) => {
      setCopiedUsageKey(null)
      setCopyErrorMessage(null)
      setDeleteConfirmationId(null)
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
      const remainingUpstreams = sortUpstreams(upstreams.filter((upstream) => upstream.id !== deletedUpstream.id))

      queryClient.setQueryData<Upstream[]>(upstreamsQueryKey(tenantId), remainingUpstreams)
      await queryClient.invalidateQueries({ queryKey: upstreamsQueryKey(tenantId) })
      setSelectedUpstreamId(remainingUpstreams[0]?.id ?? null)
      notifySuccess('Upstream deleted', `${deletedUpstream.name} has been removed.`)
    },
    onError: (error) => {
      notifyError('Upstream not deleted', getErrorMessage(error, 'Unable to delete the selected upstream right now.'))
    },
  })

  const listErrorMessage = getErrorMessage(upstreamsQuery.error, 'Unable to load upstreams right now.')
  const createErrorMessage = getErrorMessage(
    createMutation.error,
    'Unable to create the upstream with the current values.',
  )

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
    setDraft((currentDraft) => updateUpstreamDraftField(currentDraft, field, value))
    if (field === 'ecosystem') {
      const nextEcosystem = value as UpstreamEcosystem
      const nextStepCount = upstreamEcosystemSupportsAuth(nextEcosystem) ? 3 : 2
      setCreateStep((currentStep) => Math.min(currentStep, nextStepCount - 1))
    }
    setDraftErrors((currentErrors) => {
      if (!currentErrors[field]) {
        return currentErrors
      }

      const nextErrors = { ...currentErrors }
      delete nextErrors[field]
      return nextErrors
    })
  }

  function handleCapabilityToggle(capability: UpstreamCapability, checked: boolean) {
    createMutation.reset()
    setDraft((currentDraft) => toggleUpstreamDraftCapability(currentDraft, capability, checked))
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

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const validationDraft =
      createStep === 0
        ? {
            ...draft,
            authType: 'none' as const,
            authUsername: '',
            authPassword: '',
            authToken: '',
          }
        : draft
    const validation = validateUpstreamDraft(validationDraft)
    if (!validation.value) {
      setDraftErrors(validation.errors)
      return
    }

    setDraftErrors({})

    if (createStep < createReviewStep) {
      setCreateStep((currentStep) => currentStep + 1)
      return
    }

    createMutation.mutate(draft)
  }

  return (
    <section className={upstreamClass('page')}>
      <PageHeader
        eyebrow="Registry configuration"
        title="Upstreams"
        summary={
          <>
            Connect package sources for {tenantName ?? 'this tenant'}, then copy the client setup that routes installs
            through the firewall.
          </>
        }
        actions={
          <>
            <span className={upstreamClass('status-pill status-pill-neutral')}>
              {upstreamsQuery.isPending
                ? 'Loading sources'
                : upstreamsQuery.isError
                  ? 'Sources unavailable'
                  : `${upstreams.length} ${upstreams.length === 1 ? 'source' : 'sources'}`}
            </span>
            {upstreams.length > 0 ? (
              <button
                className={upstreamClass('primary-button')}
                disabled={!tenantId || createMutation.isPending}
                onClick={openCreateModal}
                type="button"
              >
                New upstream
              </button>
            ) : null}
            {!upstreamsQuery.isError ? (
              <button
                className={upstreamClass('upstreams-secondary-button')}
                disabled={upstreamsQuery.isPending || createMutation.isPending || deleteMutation.isPending}
                onClick={() => void upstreamsQuery.refetch()}
                type="button"
              >
                Refresh
              </button>
            ) : null}
          </>
        }
      />

      <div className={upstreamClass('upstreams-layout', !selectedUpstream && 'upstreams-layout-empty')}>
        <UpstreamsListPanel
          createDisabled={!tenantId || createMutation.isPending}
          errorMessage={listErrorMessage}
          isError={upstreamsQuery.isError}
          isLoading={upstreamsQuery.isPending}
          isSuccess={upstreamsQuery.isSuccess}
          onCreate={openCreateModal}
          onRetry={() => void upstreamsQuery.refetch()}
          onSelect={setSelectedUpstreamId}
          selectedUpstreamId={selectedUpstream?.id ?? null}
          upstreams={upstreams}
        />

        {selectedUpstream ? (
          <div className={upstreamClass('upstreams-stack')}>
            <UpstreamUsagePanel
              copiedUsageKey={copiedUsageKey}
              copyErrorMessage={copyErrorMessage}
              onCopyUsage={(code, key) => void handleCopyUsage(code, key)}
              upstream={selectedUpstream}
              usage={selectedUpstreamUsage}
            />

            <UpstreamDetailsPanel
              capabilities={selectedUpstreamCapabilities}
              formatTimestamp={formatUpstreamTimestamp}
              isConfirmingDelete={deleteConfirmationId === selectedUpstream.id}
              isDeleting={Boolean(deleteMutation.isPending && deleteMutation.variables?.id === selectedUpstream.id)}
              onCancelDelete={() => setDeleteConfirmationId(null)}
              onConfirmDelete={(upstream) => deleteMutation.mutate(upstream)}
              onRequestDelete={(upstream) => setDeleteConfirmationId(upstream.id)}
              policyTypes={selectedUpstreamPolicyTypes}
              upstream={selectedUpstream}
            />
          </div>
        ) : null}
      </div>

      <CreateUpstreamModal
        createErrorMessage={createErrorMessage}
        currentStep={createStep}
        draft={draft}
        draftErrors={draftErrors}
        initialFocusRef={nameInputRef}
        isError={createMutation.isError}
        isPending={createMutation.isPending}
        onBack={() => setCreateStep((currentStep) => Math.max(0, currentStep - 1))}
        onCapabilityToggle={handleCapabilityToggle}
        onClose={closeCreateModal}
        onDraftChange={handleDraftChange}
        onSubmit={handleSubmit}
        open={isCreateModalOpen}
        tenantId={tenantId}
        tenantName={tenantName}
      />
    </section>
  )
}

export function UpstreamsPage() {
  const { activeTenant, tenantId } = useTenant()

  return (
    <UpstreamsPageContent key={tenantId ?? 'no-tenant'} tenantId={tenantId} tenantName={activeTenant?.name ?? null} />
  )
}
