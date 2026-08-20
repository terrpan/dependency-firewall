import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Suspense, lazy, useMemo, useState } from 'react'
import { PageHeader } from '../ui/index.ts'
import {
  isApiError,
  asTypedPolicy,
  asTypedPolicyVersion,
  policyTypes,
  type PolicyType,
  type PolicyTypeDescriptor,
  type TypedPolicy,
  type TypedPolicyVersion,
} from '../lib/api/index.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { useSessionControlPlaneApi } from '../features/auth/useSessionControlPlaneApi.ts'
import {
  buildPolicyDraftInput,
  buildPolicyDraftPreview,
  createEmptyPolicyDraft,
  createFallbackPolicyTypeDescriptor,
  createPolicyDraftFromPolicy,
  createPolicyDraftForType,
  formatPolicyDraftJsonPreview,
  formatPolicyDraftYamlPreview,
  formatPolicyRecordJsonPreview,
  formatPolicyRecordYamlPreview,
  isPolicyDryRun,
  getSupportedActions,
  parseScorecardThresholds,
  policyDraftDefinitions,
  validatePolicyDraft,
  type PolicyDraftState,
} from '../features/policies/draft.ts'
import { matchesPolicySearch, sortPolicies } from '../features/policies/display.ts'
import { matchesPolicyFilter, type PolicyFilter } from '../features/policies/filters.ts'
import type { PolicyDetailTab } from '../features/policies/PolicyDetailModal.tsx'
import { PolicyListPanel } from '../features/policies/PolicyListPanel.tsx'
import {
  policyWizardSteps,
  type PolicyDraftFieldErrorKey,
  type PreviewFormat,
} from '../features/policies/policyDraftWizard.ts'
import { buildPolicyDiffLines } from '../features/policies/policyDiff.ts'
import { useNotifications } from '../features/notifications/useNotifications.ts'
import {
  listScopedUpstreams,
  scopedUpstreamsQueryKey,
  sortUpstreams,
  upstreamSupportsPolicyType,
  type UpstreamResourceScope,
} from '../features/upstreams/api.ts'
import { policyClass } from '../features/policies/styles.ts'

const PolicyDetailModal = lazy(() =>
  import('../features/policies/PolicyDetailModal.tsx').then(({ PolicyDetailModal }) => ({
    default: PolicyDetailModal,
  })),
)
const PolicyDiffModal = lazy(() =>
  import('../features/policies/PolicyDiffModal.tsx').then(({ PolicyDiffModal }) => ({
    default: PolicyDiffModal,
  })),
)
const PolicyDraftModal = lazy(() =>
  import('../features/policies/PolicyDraftModal.tsx').then(({ PolicyDraftModal }) => ({
    default: PolicyDraftModal,
  })),
)

function isKnownPolicyType(value: string): value is PolicyType {
  return policyTypes.includes(value as PolicyType)
}

function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message
  }

  return fallback
}

function isPositiveIntegerString(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return false
  }

  const parsed = Number(trimmed)
  return Number.isInteger(parsed) && parsed > 0
}

function isValidNumberString(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return false
  }

  return Number.isFinite(Number(trimmed))
}

export function PoliciesPage() {
  const queryClient = useQueryClient()
  const api = useSessionControlPlaneApi()
  const { notifyError, notifySuccess } = useNotifications()
  const { tenantId } = useTenant()
  const [userSelectedPolicyId, setUserSelectedPolicyId] = useState<string | null>(null)
  const [editingPolicyId, setEditingPolicyId] = useState<string | null>(null)
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const [isHistoryModalOpen, setIsHistoryModalOpen] = useState(false)
  const [selectedComparisonVersion, setSelectedComparisonVersion] = useState<TypedPolicyVersion | null>(null)
  const [policyDetailTab, setPolicyDetailTab] = useState<PolicyDetailTab>('overview')
  const [activeFilters, setActiveFilters] = useState<PolicyFilter[]>([])
  const [draftFieldErrors, setDraftFieldErrors] = useState<Partial<Record<PolicyDraftFieldErrorKey, string>>>({})
  const [policySearch, setPolicySearch] = useState('')
  const [wizardStep, setWizardStep] = useState(0)
  const [draft, setDraft] = useState<PolicyDraftState>(() => createEmptyPolicyDraft())
  const [previewFormat, setPreviewFormat] = useState<PreviewFormat>('json')
  const [diffFormat, setDiffFormat] = useState<PreviewFormat>('json')
  const [scopeValue, setScopeValue] = useState('account')
  const organizationsQuery = useQuery({ queryKey: ['organizations'], queryFn: () => api.organizations.list() })
  const resourceScope = useMemo<UpstreamResourceScope>(
    () => (scopeValue === 'account' ? { kind: 'account' } : { kind: 'organization', organizationID: scopeValue }),
    [scopeValue],
  )
  const policiesKey = [
    'scoped-policies',
    tenantId,
    resourceScope.kind,
    resourceScope.kind === 'organization' ? resourceScope.organizationID : null,
  ] as const

  const policyTypesQuery = useQuery({
    queryKey: ['policy-types'],
    queryFn: ({ signal }) => api.policies.listTypes({ signal }),
  })

  const upstreamsQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: scopedUpstreamsQueryKey(tenantId, resourceScope),
    queryFn: ({ signal }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before loading upstreams.')
      }

      return listScopedUpstreams(api, resourceScope, signal)
    },
  })

  const policiesQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: policiesKey,
    queryFn: async ({ signal }) => {
      const policies =
        resourceScope.kind === 'account'
          ? await api.scopedResources.account.policies.list({ signal })
          : await api.scopedResources.organization(resourceScope.organizationID).policies.list({ signal })
      return policies.map(asTypedPolicy).sort(sortPolicies)
    },
  })

  const fetchedDescriptors = useMemo(() => {
    const entries = (policyTypesQuery.data ?? []).flatMap(
      (descriptor): Array<readonly [PolicyType, PolicyTypeDescriptor]> =>
        isKnownPolicyType(descriptor.type) ? [[descriptor.type, descriptor]] : [],
    )

    return new Map<PolicyType, PolicyTypeDescriptor>(entries)
  }, [policyTypesQuery.data])

  const descriptors = useMemo(
    () => policyTypes.map((type) => fetchedDescriptors.get(type) ?? createFallbackPolicyTypeDescriptor(type)),
    [fetchedDescriptors],
  )
  const descriptorsByType = useMemo(
    () => new Map(descriptors.map((descriptor) => [descriptor.type as PolicyType, descriptor] as const)),
    [descriptors],
  )

  const selectedDescriptor = useMemo(
    () => (draft.type ? (descriptors.find((descriptor) => descriptor.type === draft.type) ?? null) : null),
    [descriptors, draft.type],
  )

  const policies = useMemo(() => policiesQuery.data ?? [], [policiesQuery.data])
  const upstreams = useMemo(() => sortUpstreams(upstreamsQuery.data ?? []), [upstreamsQuery.data])
  const upstreamsByID = useMemo(
    () => new Map(upstreams.map((upstream) => [upstream.id, upstream] as const)),
    [upstreams],
  )
  const selectedUpstream = useMemo(
    () => upstreams.find((upstream) => upstream.id === draft.upstreamId.trim()) ?? null,
    [draft.upstreamId, upstreams],
  )
  const compatiblePolicyTypesByUpstream = useMemo(
    () =>
      new Map(
        upstreams.map((upstream) => [
          upstream.id,
          descriptors.filter((descriptor) =>
            upstreamSupportsPolicyType(upstream, descriptor.type as PolicyType, descriptor),
          ),
        ]),
      ),
    [descriptors, upstreams],
  )
  const compatiblePolicyTypes = useMemo(
    () => (selectedUpstream ? (compatiblePolicyTypesByUpstream.get(selectedUpstream.id) ?? []) : descriptors),
    [compatiblePolicyTypesByUpstream, descriptors, selectedUpstream],
  )
  const compatibleUpstreams = useMemo(() => {
    const selectedPolicyType = draft.type
    return selectedPolicyType
      ? upstreams.filter((upstream) => upstreamSupportsPolicyType(upstream, selectedPolicyType, selectedDescriptor))
      : upstreams
  }, [draft.type, selectedDescriptor, upstreams])
  const searchedPolicies = useMemo(
    () => policies.filter((policy) => matchesPolicySearch(policy, upstreamsByID, policySearch)),
    [policies, policySearch, upstreamsByID],
  )
  const filteredPolicies = useMemo(() => {
    if (activeFilters.length === 0) {
      return searchedPolicies
    }

    return searchedPolicies.filter((policy) => activeFilters.some((filter) => matchesPolicyFilter(policy, filter)))
  }, [activeFilters, searchedPolicies])
  const filterCounts = useMemo(
    () => ({
      allow: searchedPolicies.filter((policy) => matchesPolicyFilter(policy, 'allow')).length,
      deny: searchedPolicies.filter((policy) => matchesPolicyFilter(policy, 'deny')).length,
      enabled: searchedPolicies.filter((policy) => matchesPolicyFilter(policy, 'enabled')).length,
      disabled: searchedPolicies.filter((policy) => matchesPolicyFilter(policy, 'disabled')).length,
      dry_run: searchedPolicies.filter((policy) => matchesPolicyFilter(policy, 'dry_run')).length,
    }),
    [searchedPolicies],
  )
  const selectedPolicyId = useMemo(() => {
    return userSelectedPolicyId && filteredPolicies.some((policy) => policy.id === userSelectedPolicyId)
      ? userSelectedPolicyId
      : null
  }, [filteredPolicies, userSelectedPolicyId])
  const selectedPolicy = useMemo(
    () => filteredPolicies.find((policy) => policy.id === selectedPolicyId) ?? null,
    [filteredPolicies, selectedPolicyId],
  )

  const versionsQuery = useQuery({
    enabled: Boolean(tenantId && selectedPolicyId && isHistoryModalOpen && policyDetailTab === 'history'),
    queryKey: ['policy-versions', tenantId, scopeValue, selectedPolicyId],
    queryFn: async ({ signal }) => {
      const versions = await api.policies.listVersions(selectedPolicyId ?? '', { signal })

      if (!Array.isArray(versions)) {
        return [] as TypedPolicyVersion[]
      }

      return versions.map(asTypedPolicyVersion).sort((a, b) => b.version - a.version)
    },
  })

  const supportedDraftActions = useMemo<PolicyDraftState['action'][]>(
    () => (draft.type ? getSupportedActions(draft.type, selectedDescriptor) : ['allow', 'deny']),
    [draft.type, selectedDescriptor],
  )
  const supportsLicenseAllowlistMissingBehavior = useMemo(
    () => draft.type === 'license_allowlist' && Number(draft.schemaVersion) >= 2,
    [draft.schemaVersion, draft.type],
  )
  const supportsScorecardUnavailableBehavior = draft.type === 'scorecard'
  const normalizedDraft = useMemo(() => {
    if (!draft.type || supportedDraftActions.includes(draft.action)) {
      return draft
    }

    return {
      ...draft,
      action: supportedDraftActions[0] ?? 'deny',
    }
  }, [draft, supportedDraftActions])

  const previewPolicy = useMemo(
    () => buildPolicyDraftPreview(normalizedDraft, selectedDescriptor),
    [normalizedDraft, selectedDescriptor],
  )
  const validationErrors = useMemo(
    () => validatePolicyDraft(normalizedDraft, selectedDescriptor),
    [normalizedDraft, selectedDescriptor],
  )
  const scopedPolicyError = useMemo(() => {
    if (!tenantId) {
      return 'Select a tenant before saving policies.'
    }
    if (upstreamsQuery.isError && upstreams.length === 0) {
      return upstreamsQuery.error.message
    }
    if (draft.type && normalizedDraft.upstreamId.trim() && compatibleUpstreams.length === 0) {
      return 'No upstream matches this policy type and capability profile.'
    }
    if (
      draft.type &&
      normalizedDraft.upstreamId.trim() &&
      !compatibleUpstreams.some((upstream) => upstream.id === normalizedDraft.upstreamId.trim())
    ) {
      return 'Choose an upstream that supports the selected policy type.'
    }
    return null
  }, [
    compatibleUpstreams,
    draft.type,
    normalizedDraft.upstreamId,
    tenantId,
    upstreams.length,
    upstreamsQuery.error,
    upstreamsQuery.isError,
  ])
  const reviewErrors = useMemo(
    () => (scopedPolicyError ? [scopedPolicyError, ...validationErrors] : validationErrors),
    [scopedPolicyError, validationErrors],
  )
  const jsonPreview = useMemo(() => formatPolicyDraftJsonPreview(previewPolicy), [previewPolicy])
  const yamlPreview = useMemo(() => formatPolicyDraftYamlPreview(tenantId, previewPolicy), [previewPolicy, tenantId])
  const currentPolicyDiffPreview = useMemo(
    () =>
      diffFormat === 'json'
        ? formatPolicyRecordJsonPreview(selectedPolicy)
        : formatPolicyRecordYamlPreview(selectedPolicy),
    [diffFormat, selectedPolicy],
  )
  const comparisonPolicyDiffPreview = useMemo(
    () =>
      diffFormat === 'json'
        ? formatPolicyRecordJsonPreview(selectedComparisonVersion)
        : formatPolicyRecordYamlPreview(selectedComparisonVersion),
    [diffFormat, selectedComparisonVersion],
  )
  const policyDiffLines = useMemo(
    () =>
      selectedPolicy && selectedComparisonVersion
        ? buildPolicyDiffLines(comparisonPolicyDiffPreview, currentPolicyDiffPreview)
        : [],
    [comparisonPolicyDiffPreview, currentPolicyDiffPreview, selectedComparisonVersion, selectedPolicy],
  )
  const policyDiffHasChanges = useMemo(() => policyDiffLines.some((line) => line.type !== 'context'), [policyDiffLines])

  function updatePolicyCache(nextPolicy: TypedPolicy) {
    if (!tenantId) {
      return
    }

    queryClient.setQueryData<TypedPolicy[]>(policiesKey, (currentPolicies) => {
      const nextPolicies = [...(currentPolicies ?? []).filter((policy) => policy.id !== nextPolicy.id), nextPolicy]
      return nextPolicies.sort(sortPolicies)
    })
    void queryClient.invalidateQueries({ queryKey: policiesKey })
    void queryClient.invalidateQueries({ queryKey: ['policy-versions', tenantId, scopeValue, nextPolicy.id] })
    setUserSelectedPolicyId(nextPolicy.id)
  }

  function removePolicyCache(policyID: string) {
    if (!tenantId) {
      return
    }

    queryClient.setQueryData<TypedPolicy[]>(policiesKey, (currentPolicies) =>
      (currentPolicies ?? []).filter((policy) => policy.id !== policyID),
    )
    void queryClient.invalidateQueries({ queryKey: policiesKey })
    void queryClient.invalidateQueries({ queryKey: ['policy-versions', tenantId, scopeValue, policyID] })
    setUserSelectedPolicyId((currentPolicyID) => (currentPolicyID === policyID ? null : currentPolicyID))
  }

  const savePolicyMutation = useMutation({
    mutationFn: async () => {
      if (!tenantId) {
        throw new Error('Select a tenant before saving policies.')
      }

      const policy = buildPolicyDraftInput(normalizedDraft, selectedDescriptor)
      const scopedPolicies =
        resourceScope.kind === 'account'
          ? api.scopedResources.account.policies
          : api.scopedResources.organization(resourceScope.organizationID).policies
      const saved = editingPolicyId
        ? await scopedPolicies.update(editingPolicyId, policy)
        : await scopedPolicies.create(policy)
      return asTypedPolicy(saved)
    },
    onSuccess: (savedPolicy) => {
      notifySuccess(
        editingPolicyId ? 'Policy updated' : 'Policy created',
        `${savedPolicy.name} has been ${editingPolicyId ? 'updated' : 'created'}.`,
      )
      updatePolicyCache(savedPolicy)
      setEditingPolicyId(null)
      resetDraftFlow()
      setIsCreateModalOpen(false)
    },
  })

  const togglePolicyMutation = useMutation({
    mutationFn: async ({ policy, enabled }: { policy: TypedPolicy; enabled: boolean }) => {
      const nextDraft = { ...createPolicyDraftFromPolicy(policy), enabled }
      const scopedPolicies =
        resourceScope.kind === 'account'
          ? api.scopedResources.account.policies
          : api.scopedResources.organization(resourceScope.organizationID).policies
      const updatedPolicy = await scopedPolicies.update(policy.id, buildPolicyDraftInput(nextDraft))
      return asTypedPolicy(updatedPolicy)
    },
    onSuccess: (updatedPolicy) => {
      notifySuccess('Policy updated', `${updatedPolicy.name} is now ${updatedPolicy.enabled ? 'enabled' : 'disabled'}.`)
      updatePolicyCache(updatedPolicy)

      if (editingPolicyId === updatedPolicy.id) {
        setDraft(createPolicyDraftFromPolicy(updatedPolicy))
      }
    },
    onError: (error) => {
      notifyError('Policy not updated', getErrorMessage(error, 'Unable to update the policy right now.'))
    },
  })

  const rollbackPolicyMutation = useMutation({
    mutationFn: async ({ policyId, version }: { policyId: string; version: number }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before rolling back policies.')
      }

      const rolledBack = await api.policies.rollback(policyId, { version })
      return asTypedPolicy(rolledBack)
    },
    onSuccess: (rolledBackPolicy) => {
      notifySuccess('Policy rolled back', `${rolledBackPolicy.name} has been restored.`)
      updatePolicyCache(rolledBackPolicy)
    },
    onError: (error) => {
      notifyError('Rollback failed', getErrorMessage(error, 'Unable to roll back the policy right now.'))
    },
  })
  const policyInUseDeleteMessage = 'policy has recorded evaluations or decisions'
  const deletePolicyMutation = useMutation({
    mutationFn: async ({ policy }: { force?: boolean; policy: TypedPolicy }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before deleting policies.')
      }

      const scopedPolicies =
        resourceScope.kind === 'account'
          ? api.scopedResources.account.policies
          : api.scopedResources.organization(resourceScope.organizationID).policies
      await scopedPolicies.remove(policy.id)
      return policy
    },
    onSuccess: (deletedPolicy) => {
      notifySuccess('Policy deleted', `${deletedPolicy.name} has been removed.`)
      if (editingPolicyId === deletedPolicy.id) {
        setEditingPolicyId(null)
        resetDraftFlow()
        setIsCreateModalOpen(false)
      }

      if (selectedPolicyId === deletedPolicy.id) {
        closePolicyDiff()
        closeHistoryModal()
      }

      removePolicyCache(deletedPolicy.id)
    },
    onError: (error) => {
      notifyError('Policy not deleted', getErrorMessage(error, 'Unable to delete the selected policy right now.'))
    },
  })

  const selectedDefinition = draft.type ? policyDraftDefinitions[draft.type] : null
  const selectedPolicyVersions = versionsQuery.data ?? []
  const deleteErrorMessage = getErrorMessage(
    deletePolicyMutation.error,
    'Unable to delete the selected policy right now.',
  )
  const enforcingPoliciesCount = useMemo(
    () => policies.filter((policy) => policy.enabled && !isPolicyDryRun(policy)).length,
    [policies],
  )
  const dryRunPoliciesCount = useMemo(
    () => policies.filter((policy) => policy.enabled && isPolicyDryRun(policy)).length,
    [policies],
  )
  const disabledPoliciesCount = useMemo(() => policies.filter((policy) => !policy.enabled).length, [policies])
  const isEditingPolicy = editingPolicyId !== null
  const hasCreateDraftInProgress =
    !isEditingPolicy && (draft.type !== null || draft.name.trim().length > 0 || wizardStep > 0)
  const canOpenCreateModal = Boolean(tenantId)
  const canAdvanceWizard =
    wizardStep < policyWizardSteps.length - 1 &&
    (wizardStep === 0 ? true : wizardStep === 1 ? Boolean(draft.type) : true)

  async function refreshAll() {
    await Promise.all([
      policyTypesQuery.refetch(),
      upstreamsQuery.refetch(),
      policiesQuery.refetch(),
      selectedPolicy ? versionsQuery.refetch() : Promise.resolve(),
    ])
  }

  function handleTypeSelect(type: PolicyType) {
    const descriptor = descriptors.find((item) => item.type === type) ?? createFallbackPolicyTypeDescriptor(type)

    setDraft((currentDraft) => {
      if (currentDraft.type === type) {
        return currentDraft
      }

      const nextDraft = createPolicyDraftForType(type, descriptor)
      const nextSupportedActions = getSupportedActions(type, descriptor)
      return {
        ...nextDraft,
        upstreamId: currentDraft.upstreamId,
        name: currentDraft.name,
        action: nextSupportedActions.includes(currentDraft.action) ? currentDraft.action : nextDraft.action,
        enabled: currentDraft.enabled,
      }
    })
    setDraftFieldErrors({})
    setWizardStep(2)
  }

  function handleUpstreamSelect(upstreamId: string) {
    setDraft((currentDraft) => {
      if (!upstreamId) {
        return {
          ...currentDraft,
          upstreamId: '',
          targetEnabled: false,
          targetDependencyScopes: [],
          targetDependencyTypes: [],
          targetOnUnknown: 'warn' as const,
        }
      }
      if (currentDraft.upstreamId === upstreamId) {
        return currentDraft
      }

      const nextUpstream = upstreamsByID.get(upstreamId)
      if (!nextUpstream || !currentDraft.type) {
        return {
          ...currentDraft,
          upstreamId,
          ...(nextUpstream?.ecosystem === 'npm'
            ? {}
            : {
                targetEnabled: false,
                targetDependencyScopes: [],
                targetDependencyTypes: [],
                targetOnUnknown: 'warn' as const,
              }),
        }
      }

      const currentDescriptor = descriptorsByType.get(currentDraft.type)
      if (upstreamSupportsPolicyType(nextUpstream, currentDraft.type, currentDescriptor)) {
        return {
          ...currentDraft,
          upstreamId,
          ...(nextUpstream.ecosystem === 'npm'
            ? {}
            : {
                targetEnabled: false,
                targetDependencyScopes: [],
                targetDependencyTypes: [],
                targetOnUnknown: 'warn' as const,
              }),
        }
      }

      return {
        ...currentDraft,
        upstreamId,
        type: null,
      }
    })
    setDraftFieldErrors({})
    setWizardStep(1)
  }

  function openCreateModal() {
    if (isEditingPolicy) {
      setEditingPolicyId(null)
      resetDraftFlow()
    }

    setDraftFieldErrors({})
    setIsCreateModalOpen(true)
  }

  function openEditModal(policy: TypedPolicy) {
    setEditingPolicyId(policy.id)
    savePolicyMutation.reset()
    setDraftFieldErrors({})
    setDraft(createPolicyDraftFromPolicy(policy))
    setWizardStep(0)
    setPreviewFormat('json')
    setIsCreateModalOpen(true)
  }

  function openPolicyDetail(policyId: string, tab: PolicyDetailTab = 'overview') {
    setUserSelectedPolicyId(policyId)
    setSelectedComparisonVersion(null)
    setDiffFormat('json')
    setPolicyDetailTab(tab)
    setIsHistoryModalOpen(true)
  }

  function closeHistoryModal() {
    if (rollbackPolicyMutation.isPending) {
      return
    }

    setIsHistoryModalOpen(false)
    setSelectedComparisonVersion(null)
    setDiffFormat('json')
    setPolicyDetailTab('overview')
  }

  function openPolicyDiff(version: TypedPolicyVersion) {
    setSelectedComparisonVersion(version)
    setDiffFormat('json')
  }

  function closePolicyDiff() {
    setSelectedComparisonVersion(null)
    setDiffFormat('json')
  }

  function closeCreateModal() {
    if (savePolicyMutation.isPending) {
      return
    }

    if (isEditingPolicy) {
      setEditingPolicyId(null)
      resetDraftFlow()
    }

    setIsCreateModalOpen(false)
  }

  function resetDraftFlow() {
    savePolicyMutation.reset()
    setDraftFieldErrors({})
    setDraft(createEmptyPolicyDraft())
    setWizardStep(0)
    setPreviewFormat('json')
  }

  function resetCurrentDraft() {
    if (editingPolicyId) {
      const editingPolicy = policies.find((policy) => policy.id === editingPolicyId)
      if (editingPolicy) {
        savePolicyMutation.reset()
        setDraftFieldErrors({})
        setDraft(createPolicyDraftFromPolicy(editingPolicy))
        setWizardStep(0)
        setPreviewFormat('json')
        return
      }
    }

    resetDraftFlow()
  }

  function validatePolicyStep(step: number): Partial<Record<PolicyDraftFieldErrorKey, string>> {
    const nextErrors: Partial<Record<PolicyDraftFieldErrorKey, string>> = {}

    if (step === 0) {
      if (normalizedDraft.upstreamId.trim() && !selectedUpstream) {
        nextErrors.upstreamId = 'Choose an upstream that is available in this tenant.'
      }
    }

    if (step === 1) {
      if (!draft.type) {
        nextErrors.type = 'Choose a policy type.'
      } else if (selectedUpstream && !upstreamSupportsPolicyType(selectedUpstream, draft.type, selectedDescriptor)) {
        nextErrors.type = 'Choose a policy type that matches the selected upstream.'
      }
    }

    if (step === 2) {
      if (!draft.name.trim()) {
        nextErrors.name = 'Enter a policy name.'
      }
      if (!isPositiveIntegerString(draft.priority)) {
        nextErrors.priority = 'Priority must be a positive whole number.'
      }
      if (!isPositiveIntegerString(draft.schemaVersion)) {
        nextErrors.schemaVersion = 'Choose a valid schema version.'
      }
    }

    if (step === 4 && selectedDefinition) {
      if (draft.type === 'scorecard') {
        const hasOverallThreshold = draft.numericValue.trim().length > 0
        const hasCheckThresholds = draft.listValue.trim().length > 0

        if (!hasOverallThreshold && !hasCheckThresholds) {
          nextErrors.numericValue = 'Configure an overall score, one or more check minimums, or both.'
        } else {
          if (hasOverallThreshold && !isValidNumberString(draft.numericValue)) {
            nextErrors.numericValue = 'Minimum overall score must be a valid number.'
          }
          if (hasCheckThresholds) {
            try {
              parseScorecardThresholds(draft.listValue)
            } catch (error) {
              nextErrors.listValue =
                error instanceof Error ? error.message : 'Per-check minimums must use "check=score".'
            }
          }
        }
      } else if (draft.type === 'cvss_threshold') {
        const hasCVSSThreshold = draft.useCVSSThreshold
        const hasSeverityThreshold = draft.useMinimumSeverity

        if (!hasCVSSThreshold && !hasSeverityThreshold) {
          const message = 'Enable CVSS score, minimum severity, or both.'
          nextErrors.numericValue = message
          nextErrors.minimumSeverity = message
        } else if (hasCVSSThreshold && !isValidNumberString(draft.numericValue)) {
          nextErrors.numericValue = 'Maximum CVSS score must be a valid number.'
        } else if (hasSeverityThreshold && draft.minimumSeverity.trim().length === 0) {
          nextErrors.minimumSeverity = 'Minimum severity is required when severity threshold is enabled.'
        }
      } else {
        if (selectedDefinition.numberField && !isValidNumberString(draft.numericValue)) {
          nextErrors.numericValue = `${selectedDefinition.numberLabel ?? 'Config value'} is required.`
        }
        if (selectedDefinition.listField && draft.listValue.trim().length === 0) {
          nextErrors.listValue = `${selectedDefinition.listLabel ?? 'List values'} must include at least one item.`
        }
      }
    }

    return nextErrors
  }

  function findFirstInvalidPolicyStep(fromStep: number, toStep: number) {
    for (let step = fromStep; step < toStep; step += 1) {
      const nextErrors = validatePolicyStep(step)
      if (Object.keys(nextErrors).length > 0) {
        return { step, errors: nextErrors }
      }
    }

    return null
  }

  function handleWizardStepChange(step: number) {
    if (step > wizardStep) {
      const invalidStep = findFirstInvalidPolicyStep(wizardStep, step)
      if (invalidStep) {
        setDraftFieldErrors(invalidStep.errors)
        setWizardStep(invalidStep.step)
        return
      }
    }

    setDraftFieldErrors({})
    setWizardStep(Math.min(Math.max(step, 0), policyWizardSteps.length - 1))
  }

  function updateDraft<K extends keyof PolicyDraftState>(key: K, value: PolicyDraftState[K]) {
    setDraft((currentDraft) => ({ ...currentDraft, [key]: value }))
    setDraftFieldErrors((currentErrors) => {
      if (!(key in currentErrors)) {
        return currentErrors
      }

      const nextErrors = { ...currentErrors }
      delete nextErrors[key as PolicyDraftFieldErrorKey]
      return nextErrors
    })
  }

  function handleWizardNext() {
    const nextErrors = validatePolicyStep(wizardStep)
    if (Object.keys(nextErrors).length > 0) {
      setDraftFieldErrors(nextErrors)
      return
    }

    setDraftFieldErrors({})
    setWizardStep((currentStep) => Math.min(currentStep + 1, policyWizardSteps.length - 1))
  }

  async function handleSavePolicy() {
    await savePolicyMutation.mutateAsync()
  }

  async function handleTogglePolicy(policy: TypedPolicy) {
    const nextEnabled = !policy.enabled
    const confirmed = window.confirm(`${nextEnabled ? 'Enable' : 'Disable'} policy "${policy.name}"?`)
    if (!confirmed) {
      return
    }

    await togglePolicyMutation.mutateAsync({ policy, enabled: nextEnabled })
  }

  async function handleRollback(policyId: string, version: number) {
    const confirmed = window.confirm(`Rollback policy to version ${version}?`)
    if (!confirmed) {
      return
    }

    await rollbackPolicyMutation.mutateAsync({ policyId, version })
  }

  async function handleDeletePolicy(policy: TypedPolicy) {
    deletePolicyMutation.reset()
    if (policy.enabled) {
      return
    }
    const confirmed = window.confirm(`Delete policy "${policy.name}"?`)
    if (!confirmed) {
      return
    }

    try {
      await deletePolicyMutation.mutateAsync({ policy })
    } catch (error) {
      if (!isApiError(error) || error.message !== policyInUseDeleteMessage) {
        return
      }

      deletePolicyMutation.reset()
      const forceConfirmed = window.confirm(
        `Force delete policy "${policy.name}"?\n\nThis detaches historical evaluations and decisions from the policy and removes its retained versions.`,
      )
      if (!forceConfirmed) {
        return
      }

      await deletePolicyMutation.mutateAsync({ force: true, policy })
    }
  }

  function toggleFilter(filter: PolicyFilter) {
    setActiveFilters((currentFilters) =>
      currentFilters.includes(filter)
        ? currentFilters.filter((currentFilter) => currentFilter !== filter)
        : [...currentFilters, filter],
    )
  }

  return (
    <section className={policyClass('page')}>
      <PageHeader
        eyebrow="Policy control plane"
        title="Policies"
        summary="Manage account-wide rules or rules inherited only by a selected local Organization."
        actions={
          <>
            <select
              aria-label="Policy scope"
              className={policyClass('policies-scope-select')}
              onChange={(event) => setScopeValue(event.target.value)}
              value={scopeValue}
            >
              <option value="account">Account policies</option>
              {organizationsQuery.data?.map((organization) => (
                <option key={organization.id} value={organization.id}>
                  Organization: {organization.name}
                </option>
              ))}
            </select>
            <span className={policyClass('status-pill status-pill-neutral')}>{policies.length} policies</span>
            <span
              className={policyClass(
                'status-pill',
                enforcingPoliciesCount > 0 ? 'status-pill-success' : 'status-pill-neutral',
              )}
            >
              {enforcingPoliciesCount} enforcing
            </span>
            {dryRunPoliciesCount > 0 ? (
              <span className={policyClass('status-pill status-pill-warning')}>{dryRunPoliciesCount} dry run</span>
            ) : null}
            {disabledPoliciesCount > 0 ? (
              <span className={policyClass('status-pill status-pill-neutral')}>{disabledPoliciesCount} disabled</span>
            ) : null}
            {policyTypesQuery.isError ? (
              <span className={policyClass('status-pill status-pill-neutral')}>Fallback metadata</span>
            ) : null}
          </>
        }
      />

      <div className={policyClass('policies-layout')}>
        <PolicyListPanel
          activeFilters={activeFilters}
          canOpenCreateModal={canOpenCreateModal}
          canRefresh={
            !policyTypesQuery.isFetching &&
            !upstreamsQuery.isFetching &&
            !policiesQuery.isFetching &&
            !versionsQuery.isFetching
          }
          deleteErrorMessage={deleteErrorMessage}
          deletePendingPolicyId={
            deletePolicyMutation.isPending ? (deletePolicyMutation.variables?.policy.id ?? null) : null
          }
          filterCounts={filterCounts}
          filteredPolicies={filteredPolicies}
          hasCreateDraftInProgress={hasCreateDraftInProgress}
          isDeleteError={deletePolicyMutation.isError}
          isPoliciesError={policiesQuery.isError}
          isPoliciesFetching={policiesQuery.isFetching}
          isUpstreamsFetching={upstreamsQuery.isFetching}
          onClearFilters={() => {
            setPolicySearch('')
            setActiveFilters([])
          }}
          onDelete={(policy) => void handleDeletePolicy(policy)}
          onEdit={openEditModal}
          onOpenCreate={openCreateModal}
          onOpenDetail={openPolicyDetail}
          onRefresh={() => void refreshAll()}
          onSearchChange={setPolicySearch}
          onToggleFilter={toggleFilter}
          onTogglePolicy={(policy) => void handleTogglePolicy(policy)}
          policies={policies}
          policiesErrorMessage={policiesQuery.isError ? policiesQuery.error.message : null}
          policySearch={policySearch}
          selectedPolicyId={selectedPolicyId}
          togglePendingPolicyId={
            togglePolicyMutation.isPending ? (togglePolicyMutation.variables?.policy.id ?? null) : null
          }
          upstreamsByID={upstreamsByID}
          upstreamsCount={upstreams.length}
        />
      </div>

      {isHistoryModalOpen ? (
        <Suspense fallback={null}>
          <PolicyDetailModal
            deleteErrorMessage={deleteErrorMessage}
            deletePendingPolicyId={
              deletePolicyMutation.isPending ? (deletePolicyMutation.variables?.policy.id ?? null) : null
            }
            detailTab={policyDetailTab}
            hasOpenDiff={Boolean(selectedComparisonVersion)}
            isDeleteError={deletePolicyMutation.isError}
            isOpen={isHistoryModalOpen}
            isRollbackError={rollbackPolicyMutation.isError}
            isRollbackPending={rollbackPolicyMutation.isPending}
            isVersionsError={versionsQuery.isError}
            isVersionsPending={versionsQuery.isPending}
            onClose={closeHistoryModal}
            onDelete={(policy) => void handleDeletePolicy(policy)}
            onDetailTabChange={setPolicyDetailTab}
            onOpenDiff={openPolicyDiff}
            onRollback={(policyId, version) => void handleRollback(policyId, version)}
            onTogglePolicy={(policy) => void handleTogglePolicy(policy)}
            policy={selectedPolicy}
            rollbackErrorMessage={rollbackPolicyMutation.isError ? rollbackPolicyMutation.error.message : null}
            togglePendingPolicyId={
              togglePolicyMutation.isPending ? (togglePolicyMutation.variables?.policy.id ?? null) : null
            }
            upstreamsByID={upstreamsByID}
            versions={selectedPolicyVersions}
            versionsErrorMessage={versionsQuery.isError ? versionsQuery.error.message : null}
          />
        </Suspense>
      ) : null}

      {selectedComparisonVersion ? (
        <Suspense fallback={null}>
          <PolicyDiffModal
            comparisonVersion={selectedComparisonVersion}
            currentPolicy={selectedPolicy}
            diffFormat={diffFormat}
            diffLines={policyDiffLines}
            hasChanges={policyDiffHasChanges}
            onClose={closePolicyDiff}
            onFormatChange={setDiffFormat}
          />
        </Suspense>
      ) : null}

      {isCreateModalOpen ? (
        <Suspense fallback={null}>
          <PolicyDraftModal
            canAdvanceWizard={canAdvanceWizard}
            compatiblePolicyTypes={compatiblePolicyTypes}
            compatiblePolicyTypesByUpstream={compatiblePolicyTypesByUpstream}
            currentStep={wizardStep}
            draft={draft}
            draftFieldErrors={draftFieldErrors}
            hasCreateDraftInProgress={hasCreateDraftInProgress}
            isEditingPolicy={isEditingPolicy}
            jsonPreview={jsonPreview}
            normalizedDraft={normalizedDraft}
            onBack={() => {
              setDraftFieldErrors({})
              setWizardStep((currentStep) => Math.max(currentStep - 1, 0))
            }}
            onClose={closeCreateModal}
            onDraftChange={updateDraft}
            onNext={handleWizardNext}
            onPreviewFormatChange={setPreviewFormat}
            onResetDraft={resetCurrentDraft}
            onSavePolicy={() => void handleSavePolicy()}
            onStepChange={handleWizardStepChange}
            onTypeSelect={handleTypeSelect}
            onUpstreamSelect={handleUpstreamSelect}
            open={isCreateModalOpen}
            policyTypesIsError={policyTypesQuery.isError}
            previewFormat={previewFormat}
            reviewErrors={reviewErrors}
            savePolicyErrorMessage={savePolicyMutation.isError ? savePolicyMutation.error.message : null}
            savePolicyIsError={savePolicyMutation.isError}
            savePolicyIsPending={savePolicyMutation.isPending}
            selectedDefinition={selectedDefinition}
            selectedDescriptor={selectedDescriptor}
            selectedUpstream={selectedUpstream}
            supportedDraftActions={supportedDraftActions}
            supportsLicenseAllowlistMissingBehavior={supportsLicenseAllowlistMissingBehavior}
            supportsScorecardUnavailableBehavior={supportsScorecardUnavailableBehavior}
            tenantId={tenantId}
            upstreams={upstreams}
            upstreamsErrorMessage={upstreamsQuery.isError ? upstreamsQuery.error.message : null}
            upstreamsIsError={upstreamsQuery.isError}
            upstreamsIsPending={upstreamsQuery.isPending}
            yamlPreview={yamlPreview}
          />
        </Suspense>
      ) : null}
    </section>
  )
}
