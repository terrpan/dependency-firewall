import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import {
  SearchFilterBar,
  type FilterChipOption,
} from '../components/filters/SearchFilterBar.tsx'
import {
  isApiError,
  asTypedPolicy,
  asTypedPolicyVersion,
  policyTypes,
  type PolicyType,
  type PolicyTypeDescriptor,
  type TypedPolicy,
  type TypedPolicyVersion,
  type Upstream,
} from '../lib/api/index.ts'
import { ModalDialog, ModalWizard, type ModalWizardStep } from '../components/modal/index.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { useTenantControlPlaneApi } from '../features/tenant/useTenantControlPlaneApi.ts'
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
  getPolicyTypeLabel,
  getSupportedActions,
  isPolicyDryRun,
  policyDraftDefinitions,
  validatePolicyDraft,
  type PolicyDraftState,
} from '../features/policies/draft.ts'
import { useNotifications } from '../features/notifications/useNotifications.ts'
import {
  formatUpstreamCapabilityLabel,
  listUpstreams,
  sortUpstreams,
  upstreamSupportsPolicyType,
  upstreamsQueryKey,
} from '../features/upstreams/api.ts'

const policyWizardSteps = [
  {
    id: 'choose-upstream',
    label: 'Choose upstream',
    description: 'Select the upstream scope.',
  },
  {
    id: 'choose-type',
    label: 'Choose type',
    description: 'Pick a compatible policy type.',
  },
  {
    id: 'set-basics',
    label: 'Set basics',
    description: 'Set the name and defaults.',
  },
  {
    id: 'configure-rule',
    label: 'Configure rule',
    description: 'Add the rule values.',
  },
  {
    id: 'review-create',
    label: 'Review and create',
    description: 'Review the preview and save.',
  },
] satisfies readonly ModalWizardStep[]

type PreviewFormat = 'json' | 'yaml'
type PolicyFilter = 'enabled' | 'disabled' | 'dry_run' | 'allow' | 'deny'
type PolicyDetailTab = 'overview' | 'history'
type PolicyDisplayRecord = TypedPolicy | TypedPolicyVersion
type PolicyDraftFieldErrorKey =
  | 'type'
  | 'upstreamId'
  | 'name'
  | 'priority'
  | 'schemaVersion'
  | 'numericValue'
  | 'listValue'
type PolicyDiffLine = {
  type: 'added' | 'removed' | 'context'
  oldLineNumber: number | null
  newLineNumber: number | null
  content: string
}

const policyFilterOptions = [
  { id: 'deny', label: 'Deny', tone: 'danger' },
  { id: 'allow', label: 'Allow', tone: 'success' },
  { id: 'enabled', label: 'Enabled', tone: 'info' },
  { id: 'disabled', label: 'Disabled', tone: 'muted' },
  { id: 'dry_run', label: 'Dry run', tone: 'warning' },
] satisfies readonly FilterChipOption<PolicyFilter>[]

const timestampFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

function isKnownPolicyType(value: string): value is PolicyType {
  return policyTypes.includes(value as PolicyType)
}

function formatTimestamp(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? value : timestampFormatter.format(date)
}

function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message
  }

  return fallback
}

function sortPolicies(a: TypedPolicy, b: TypedPolicy) {
  return a.priority - b.priority || a.name.localeCompare(b.name)
}

function formatUpstreamOptionLabel(upstream: Upstream) {
  return `${upstream.name} (${upstream.ecosystem.toUpperCase()})`
}

function formatPolicyScopeLabel(policy: PolicyDisplayRecord, upstreamsByID: Map<string, Upstream>) {
  const upstreamID = policy.upstream_id?.trim()
  if (!upstreamID) {
    return 'Tenant-wide (legacy)'
  }

  const upstream = upstreamsByID.get(upstreamID)
  return upstream ? formatUpstreamOptionLabel(upstream) : `Upstream ${upstreamID}`
}

function formatPolicyScopeCaption(policy: PolicyDisplayRecord, upstreamsByID: Map<string, Upstream>) {
  const upstreamID = policy.upstream_id?.trim()
  if (!upstreamID) {
    return 'Legacy tenant-wide scope'
  }

  const upstream = upstreamsByID.get(upstreamID)
  return upstream
    ? `Scoped to ${upstream.ecosystem.toUpperCase()} upstream ${upstream.name}`
    : `Scoped to upstream ${upstreamID}`
}

function getActionTone(action: string) {
  return action === 'deny' ? 'policy-badge-danger' : 'policy-badge-success'
}

function getEnabledTone(enabled: boolean) {
  return enabled ? 'policy-badge-info' : 'policy-badge-muted'
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

function formatLicenseAllowlistBehaviorLabel(value?: string) {
  return value === 'skip' ? 'Skip this policy' : 'Deny artifact'
}

function matchesPolicyFilter(policy: TypedPolicy, filter: PolicyFilter) {
  if (filter === 'enabled') {
    return policy.enabled
  }

  if (filter === 'disabled') {
    return !policy.enabled
  }

  if (filter === 'allow') {
    return policy.action === 'allow'
  }

  if (filter === 'deny') {
    return policy.action === 'deny'
  }

  return isPolicyDryRun(policy)
}

function getSchemaVersions(descriptor: PolicyTypeDescriptor) {
  return descriptor.supported_schema_versions?.length
    ? descriptor.supported_schema_versions
    : [descriptor.current_schema_version]
}

function getSupportedEcosystems(descriptor: PolicyTypeDescriptor): string[] {
  return descriptor.supported_ecosystems?.length ? descriptor.supported_ecosystems : ['npm', 'oci']
}

function getRequiredCapabilities(descriptor: PolicyTypeDescriptor): string[] {
  return descriptor.required_capabilities ?? []
}

function summarizeListValues(values: string[]) {
  if (values.length === 0) {
    return 'None'
  }

  const head = values.slice(0, 2).join(', ')
  const suffix = values.length > 2 ? ` +${values.length - 2} more` : ''
  return `${head}${suffix}`
}

function getPolicyConfigFields(policy: PolicyDisplayRecord): Array<{ label: string; values: string[] }> {
  switch (policy.type) {
    case 'cvss_threshold':
      return [{ label: 'Max CVSS', values: [String(policy.config.max_cvss)] }]
    case 'minimum_age': {
      const fields = [{ label: 'Minimum age', values: [`${policy.config.min_age_days} days`] }]
      if (policy.config.exclude_packages?.length) {
        fields.push({ label: 'Excluded packages', values: policy.config.exclude_packages })
      }
      return fields
    }
    case 'maximum_age': {
      const fields = [{ label: 'Maximum age', values: [`${policy.config.max_age_days} days`] }]
      if (policy.config.exclude_packages?.length) {
        fields.push({ label: 'Excluded packages', values: policy.config.exclude_packages })
      }
      return fields
    }
    case 'block_mutable_tag':
      return [{ label: 'Tags', values: policy.config.tags }]
    case 'license':
      return [{ label: 'Licenses', values: policy.config.licenses }]
    case 'license_allowlist':
      return [
        { label: 'Approved licenses', values: policy.config.licenses },
        ...(policy.schema_version >= 2
          ? [
              {
                label: 'When unlicensed',
                values: [formatLicenseAllowlistBehaviorLabel(policy.config.unlicensed_behavior)],
              },
              {
                label: 'When metadata unavailable',
                values: [formatLicenseAllowlistBehaviorLabel(policy.config.unavailable_metadata_behavior)],
              },
            ]
          : []),
      ]
    case 'allowlist':
      return [{ label: 'Namespaces', values: policy.config.namespaces }]
    case 'namespace_allowlist':
      return [{ label: 'Approved namespaces', values: policy.config.namespaces }]
    case 'blocklist':
      return [{ label: 'Blocked namespaces', values: policy.config.namespaces }]
  }
}

function getPolicyConfigDetail(policy: PolicyDisplayRecord) {
  const [primaryField, ...extraFields] = getPolicyConfigFields(policy)
  if (!primaryField) {
    return { label: 'Configuration', value: 'No configuration values' }
  }

  const primaryValue =
    primaryField.values.length <= 1 ? primaryField.values[0] ?? 'No value' : summarizeListValues(primaryField.values)

  return {
    label: primaryField.label,
    value: extraFields.length > 0 ? `${primaryValue} • +${extraFields.length} more` : primaryValue,
  }
}

function matchesPolicySearch(policy: TypedPolicy, upstreamsByID: Map<string, Upstream>, query: string) {
  const normalizedQuery = query.trim().toLowerCase()
  if (!normalizedQuery) {
    return true
  }

  const configDetail = getPolicyConfigDetail(policy)
  const searchableFields = [
    policy.name,
    policy.id,
    policy.type,
    getPolicyTypeLabel(policy.type),
    policy.action,
    formatPolicyScopeLabel(policy, upstreamsByID),
    formatPolicyScopeCaption(policy, upstreamsByID),
    configDetail.label,
    configDetail.value,
  ]

  return searchableFields.some((field) => field.toLowerCase().includes(normalizedQuery))
}

function splitPreviewLines(value: string) {
  return value === '' ? [''] : value.split('\n')
}

function buildPolicyDiffLines(previousContent: string, currentContent: string): PolicyDiffLine[] {
  const previousLines = splitPreviewLines(previousContent)
  const currentLines = splitPreviewLines(currentContent)
  const lcsTable = Array.from({ length: previousLines.length + 1 }, () =>
    Array<number>(currentLines.length + 1).fill(0),
  )

  for (let previousIndex = previousLines.length - 1; previousIndex >= 0; previousIndex -= 1) {
    for (let currentIndex = currentLines.length - 1; currentIndex >= 0; currentIndex -= 1) {
      lcsTable[previousIndex][currentIndex] =
        previousLines[previousIndex] === currentLines[currentIndex]
          ? lcsTable[previousIndex + 1][currentIndex + 1] + 1
          : Math.max(lcsTable[previousIndex + 1][currentIndex], lcsTable[previousIndex][currentIndex + 1])
    }
  }

  const diffLines: PolicyDiffLine[] = []
  let previousIndex = 0
  let currentIndex = 0
  let previousLineNumber = 1
  let currentLineNumber = 1

  while (previousIndex < previousLines.length && currentIndex < currentLines.length) {
    if (previousLines[previousIndex] === currentLines[currentIndex]) {
      diffLines.push({
        type: 'context',
        oldLineNumber: previousLineNumber,
        newLineNumber: currentLineNumber,
        content: previousLines[previousIndex] ?? '',
      })
      previousIndex += 1
      currentIndex += 1
      previousLineNumber += 1
      currentLineNumber += 1
      continue
    }

    if (lcsTable[previousIndex + 1][currentIndex] >= lcsTable[previousIndex][currentIndex + 1]) {
      diffLines.push({
        type: 'removed',
        oldLineNumber: previousLineNumber,
        newLineNumber: null,
        content: previousLines[previousIndex] ?? '',
      })
      previousIndex += 1
      previousLineNumber += 1
      continue
    }

    diffLines.push({
      type: 'added',
      oldLineNumber: null,
      newLineNumber: currentLineNumber,
      content: currentLines[currentIndex] ?? '',
    })
    currentIndex += 1
    currentLineNumber += 1
  }

  while (previousIndex < previousLines.length) {
    diffLines.push({
      type: 'removed',
      oldLineNumber: previousLineNumber,
      newLineNumber: null,
      content: previousLines[previousIndex] ?? '',
    })
    previousIndex += 1
    previousLineNumber += 1
  }

  while (currentIndex < currentLines.length) {
    diffLines.push({
      type: 'added',
      oldLineNumber: null,
      newLineNumber: currentLineNumber,
      content: currentLines[currentIndex] ?? '',
    })
    currentIndex += 1
    currentLineNumber += 1
  }

  return diffLines
}

export function PoliciesPage() {
  const queryClient = useQueryClient()
  const api = useTenantControlPlaneApi()
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

  const policyTypesQuery = useQuery({
    queryKey: ['policy-types'],
    queryFn: ({ signal }) => api.policies.listTypes({ signal }),
  })

  const upstreamsQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: upstreamsQueryKey(tenantId),
    queryFn: ({ signal }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before loading upstreams.')
      }

      return listUpstreams(api, tenantId, signal)
    },
  })

  const policiesQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: ['policies', tenantId],
    queryFn: async ({ signal }) => {
      const policies = await api.policies.list({ signal })
      return policies.map(asTypedPolicy).sort(sortPolicies)
    },
  })

  const fetchedDescriptors = useMemo(() => {
    const entries = (policyTypesQuery.data ?? []).flatMap((descriptor) =>
      isKnownPolicyType(descriptor.type) ? ([[descriptor.type, descriptor]] as const) : [],
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
    () => (draft.type ? descriptors.find((descriptor) => descriptor.type === draft.type) ?? null : null),
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
    () => (selectedUpstream ? compatiblePolicyTypesByUpstream.get(selectedUpstream.id) ?? [] : []),
    [compatiblePolicyTypesByUpstream, selectedUpstream],
  )
  const compatibleUpstreams = useMemo(
    () =>
      draft.type
        ? upstreams.filter((upstream) => upstreamSupportsPolicyType(upstream, draft.type, selectedDescriptor))
        : upstreams,
    [draft.type, selectedDescriptor, upstreams],
  )
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
    if (filteredPolicies.length === 0) {
      return null
    }

    return userSelectedPolicyId && filteredPolicies.some((policy) => policy.id === userSelectedPolicyId)
      ? userSelectedPolicyId
      : filteredPolicies[0].id
  }, [filteredPolicies, userSelectedPolicyId])
  const selectedPolicy = useMemo(
    () => filteredPolicies.find((policy) => policy.id === selectedPolicyId) ?? null,
    [filteredPolicies, selectedPolicyId],
  )

  const versionsQuery = useQuery({
    enabled: Boolean(tenantId && selectedPolicyId && isHistoryModalOpen && policyDetailTab === 'history'),
    queryKey: ['policy-versions', tenantId, selectedPolicyId],
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
    if (upstreamsQuery.isPending && upstreams.length === 0) {
      return 'Wait for upstreams to load before saving this policy.'
    }
    if (upstreams.length === 0) {
      return 'Create an upstream before saving policies.'
    }
    if (draft.type && compatibleUpstreams.length === 0) {
      return 'No upstream matches this policy type and capability profile.'
    }
    if (!normalizedDraft.upstreamId.trim()) {
      return 'Choose the upstream this policy applies to.'
    }
    if (
      draft.type &&
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
    upstreamsQuery.isPending,
  ])
  const reviewErrors = useMemo(
    () => (scopedPolicyError ? [scopedPolicyError, ...validationErrors] : validationErrors),
    [scopedPolicyError, validationErrors],
  )
  const jsonPreview = useMemo(
    () => formatPolicyDraftJsonPreview(previewPolicy),
    [previewPolicy],
  )
  const yamlPreview = useMemo(
    () => formatPolicyDraftYamlPreview(tenantId, previewPolicy),
    [previewPolicy, tenantId],
  )
  const currentPolicyWizardStep = policyWizardSteps[wizardStep] ?? null
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
  const policyDiffHasChanges = useMemo(
    () => policyDiffLines.some((line) => line.type !== 'context'),
    [policyDiffLines],
  )

  function updatePolicyCache(nextPolicy: TypedPolicy) {
    if (!tenantId) {
      return
    }

    queryClient.setQueryData<TypedPolicy[]>(['policies', tenantId], (currentPolicies) => {
      const nextPolicies = [...(currentPolicies ?? []).filter((policy) => policy.id !== nextPolicy.id), nextPolicy]
      return nextPolicies.sort(sortPolicies)
    })
    void queryClient.invalidateQueries({ queryKey: ['policies', tenantId] })
    void queryClient.invalidateQueries({ queryKey: ['policy-versions', tenantId, nextPolicy.id] })
    setUserSelectedPolicyId(nextPolicy.id)
  }

  function removePolicyCache(policyID: string) {
    if (!tenantId) {
      return
    }

    queryClient.setQueryData<TypedPolicy[]>(['policies', tenantId], (currentPolicies) =>
      (currentPolicies ?? []).filter((policy) => policy.id !== policyID),
    )
    void queryClient.invalidateQueries({ queryKey: ['policies', tenantId] })
    void queryClient.invalidateQueries({ queryKey: ['policy-versions', tenantId, policyID] })
    setUserSelectedPolicyId((currentPolicyID) => (currentPolicyID === policyID ? null : currentPolicyID))
  }

  const savePolicyMutation = useMutation({
    mutationFn: async () => {
      if (!tenantId) {
        throw new Error('Select a tenant before saving policies.')
      }

      const policy = buildPolicyDraftInput(normalizedDraft, selectedDescriptor)
      const saved = editingPolicyId
        ? await api.policies.update(editingPolicyId, policy)
        : await api.policies.create(policy)
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
      const updatedPolicy = await api.policies.update(policy.id, buildPolicyDraftInput(nextDraft))
      return asTypedPolicy(updatedPolicy)
    },
    onSuccess: (updatedPolicy) => {
      notifySuccess(
        'Policy updated',
        `${updatedPolicy.name} is now ${updatedPolicy.enabled ? 'enabled' : 'disabled'}.`,
      )
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
    mutationFn: async ({ force, policy }: { force?: boolean; policy: TypedPolicy }) => {
      if (!tenantId) {
        throw new Error('Select a tenant before deleting policies.')
      }

      await api.policies.remove(policy.id, { force })
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
  const currentPolicyTypeLabel = selectedPolicy ? getPolicyTypeLabel(selectedPolicy.type) : null
  const deleteErrorMessage = getErrorMessage(
    deletePolicyMutation.error,
    'Unable to delete the selected policy right now.',
  )
  const enabledPoliciesCount = useMemo(
    () => policies.filter((policy) => policy.enabled).length,
    [policies],
  )
  const dryRunPoliciesCount = useMemo(
    () => policies.filter((policy) => isPolicyDryRun(policy)).length,
    [policies],
  )
  const isEditingPolicy = editingPolicyId !== null
  const hasCreateDraftInProgress = !isEditingPolicy && (draft.type !== null || draft.name.trim().length > 0 || wizardStep > 0)
  const canOpenCreateModal = Boolean(tenantId) && !upstreamsQuery.isPending && upstreams.length > 0
  const canAdvanceWizard =
    wizardStep < policyWizardSteps.length - 1 &&
    (wizardStep === 0
      ? Boolean(normalizedDraft.upstreamId.trim())
      : wizardStep === 1
        ? Boolean(draft.type)
        : true)

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
      if (currentDraft.upstreamId === upstreamId) {
        return currentDraft
      }

      const nextUpstream = upstreamsByID.get(upstreamId)
      if (!nextUpstream || !currentDraft.type) {
        return {
          ...currentDraft,
          upstreamId,
        }
      }

      const currentDescriptor = descriptorsByType.get(currentDraft.type)
      if (upstreamSupportsPolicyType(nextUpstream, currentDraft.type, currentDescriptor)) {
        return {
          ...currentDraft,
          upstreamId,
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
      if (!normalizedDraft.upstreamId.trim()) {
        nextErrors.upstreamId = 'Choose the upstream this policy applies to.'
      } else if (!selectedUpstream) {
        nextErrors.upstreamId = 'Choose an upstream that is available in this tenant.'
      }
    }

    if (step === 1) {
      if (!draft.type) {
        nextErrors.type = 'Choose a policy type.'
      } else if (
        selectedUpstream &&
        !upstreamSupportsPolicyType(selectedUpstream, draft.type, selectedDescriptor)
      ) {
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

    if (step === 3 && selectedDefinition) {
      if (selectedDefinition.numberField && !isValidNumberString(draft.numericValue)) {
        nextErrors.numericValue = `${selectedDefinition.numberLabel ?? 'Config value'} is required.`
      }
      if (selectedDefinition.listField && draft.listValue.trim().length === 0) {
        nextErrors.listValue = `${selectedDefinition.listLabel ?? 'List values'} must include at least one item.`
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
    const confirmed = window.confirm(
      `${nextEnabled ? 'Enable' : 'Disable'} policy "${policy.name}"?`,
    )
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
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Policy control plane</p>
          <h2>Policies</h2>
          <p className="page-summary">
            Browse current rules, open a detailed policy view on demand, and keep creation in a popup
            that preserves your place.
          </p>
        </div>
        <div className="policies-header-status">
          {tenantId ? <span className="status-pill status-pill-neutral">Tenant scoped</span> : null}
          <span className="status-pill status-pill-neutral">{policies.length} policies</span>
          <span className="status-pill status-pill-neutral">{upstreams.length} upstreams</span>
          <span
            className={`status-pill ${enabledPoliciesCount > 0 ? 'status-pill-success' : 'status-pill-neutral'}`}
          >
            {enabledPoliciesCount} enabled
          </span>
          <span className="status-pill status-pill-neutral">{dryRunPoliciesCount} dry run</span>
          {policyTypesQuery.isError ? (
            <span className="status-pill status-pill-neutral">Fallback metadata</span>
          ) : null}
        </div>
      </header>

      <div className="policies-layout">
        <section className="card policy-list-card">
          <div className="policy-section-heading">
            <div>
              <p className="eyebrow">Policies list</p>
              <h3>Current tenant policies</h3>
              <p className="muted">
                Priority order mirrors evaluation order while each card can open a detailed overview
                or jump straight to history.
              </p>
            </div>
            <div className="policy-list-tools">
              {activeFilters.length > 0 || policySearch.trim() ? (
                <span className="status-pill status-pill-neutral">{filteredPolicies.length} shown</span>
              ) : null}
              {upstreamsQuery.isFetching ? <span className="status-pill status-pill-neutral">Loading upstreams</span> : null}
              {policiesQuery.isFetching ? <span className="status-pill status-pill-neutral">Refreshing</span> : null}
              <button
                className="secondary-button"
                disabled={
                  policyTypesQuery.isFetching ||
                  upstreamsQuery.isFetching ||
                  policiesQuery.isFetching ||
                  versionsQuery.isFetching
                }
                onClick={() => void refreshAll()}
                type="button"
              >
                Refresh
              </button>
              <button className="primary-button" disabled={!canOpenCreateModal} onClick={openCreateModal} type="button">
                {hasCreateDraftInProgress ? 'Resume draft' : 'New policy'}
              </button>
            </div>
          </div>

          {policiesQuery.isError ? (
            <div className="policy-error-panel">
              <h4>Unable to load policies</h4>
              <p className="muted">{policiesQuery.error.message}</p>
            </div>
          ) : null}

          {deletePolicyMutation.isError ? (
            <div className="policy-error-panel">
              <h4>Unable to delete policy</h4>
              <p className="muted">{deleteErrorMessage}</p>
            </div>
          ) : null}

          <SearchFilterBar
            activeFilters={activeFilters}
            clearFiltersLabel="Clear filters"
            filterGroupLabel="Policy filters"
            filterOptions={policyFilterOptions.map((filter) => ({
              ...filter,
              count: filterCounts[filter.id],
            }))}
            onClearFilters={() => setActiveFilters([])}
            onSearchChange={setPolicySearch}
            onToggleFilter={toggleFilter}
            searchHelpText="Search by policy name, type, action, upstream scope, or configuration summary."
            searchInputId="policy-search"
            searchLabel="Policy search"
            searchPlaceholder="block_cvss, cvss_threshold, npm upstream..."
            searchValue={policySearch}
          />

          {!policiesQuery.isError && policies.length === 0 ? (
            <div className="policy-empty-state">
              <h4>No policies yet</h4>
              <p className="muted">
                {upstreams.length === 0
                  ? 'Create an upstream first, then open the guided popup to scope the first policy to it.'
                  : 'Open the guided popup to create the first policy without leaving this page.'}
              </p>
              <div className="policy-empty-actions">
                <button className="primary-button" disabled={!canOpenCreateModal} onClick={openCreateModal} type="button">
                  Create first policy
                </button>
              </div>
            </div>
          ) : null}

          {!policiesQuery.isError && policies.length > 0 && filteredPolicies.length === 0 ? (
            <div className="policy-empty-state">
              <h4>No policies match this search and filter state</h4>
              <p className="muted">Try a different search or filter combination to bring matching policies back into view.</p>
              <div className="policy-empty-actions">
                <button
                  className="secondary-button"
                  onClick={() => {
                    setPolicySearch('')
                    setActiveFilters([])
                  }}
                  type="button"
                >
                  Clear filters
                </button>
              </div>
            </div>
          ) : null}

          <div className="policy-list" role="list">
            {filteredPolicies.map((policy) => (
              <article
                key={policy.id}
                className={`policy-list-item${policy.id === selectedPolicyId ? ' selected' : ''}`}
              >
                <button
                  className="policy-list-item-main"
                  onClick={() => openPolicyDetail(policy.id)}
                  type="button"
                >
                  <div className="policy-list-item-header">
                    <div>
                      <h4>{policy.name}</h4>
                      <p className="muted">{getPolicyTypeLabel(policy.type)}</p>
                      <p className="policy-scope-copy">{formatPolicyScopeCaption(policy, upstreamsByID)}</p>
                    </div>
                    <div className="policy-list-item-badges">
                      <span className={`policy-badge ${getActionTone(policy.action)}`}>{policy.action}</span>
                      <span className={`policy-badge ${getEnabledTone(policy.enabled)}`}>
                        {policy.enabled ? 'enabled' : 'disabled'}
                      </span>
                      {isPolicyDryRun(policy) ? <span className="policy-badge policy-badge-muted">dry run</span> : null}
                    </div>
                  </div>
                  <div className="policy-config-summary">
                    <span className="policy-config-label">{getPolicyConfigDetail(policy).label}</span>
                    <span className="policy-config-value">{getPolicyConfigDetail(policy).value}</span>
                  </div>
                  <dl className="metadata-list compact-metadata-list compact-metadata-list-dense">
                    <div>
                      <dt>Scope</dt>
                      <dd>{formatPolicyScopeLabel(policy, upstreamsByID)}</dd>
                    </div>
                    <div>
                      <dt>Priority</dt>
                      <dd>{policy.priority}</dd>
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
                      <dd>{formatTimestamp(policy.created_at)}</dd>
                    </div>
                    <div>
                      <dt>Updated</dt>
                      <dd>{formatTimestamp(policy.updated_at)}</dd>
                    </div>
                  </dl>
                </button>

                <div className="policy-list-item-footer">
                  <div className="policy-list-item-actions">
                    <button className="policy-card-action" onClick={() => openEditModal(policy)} type="button">
                      Edit
                    </button>
                    <button className="policy-card-action" onClick={() => openPolicyDetail(policy.id, 'history')} type="button">
                      History
                    </button>
                    <button
                      className="policy-card-action policy-card-action-danger"
                      disabled={policy.enabled || deletePolicyMutation.isPending}
                      onClick={() => void handleDeletePolicy(policy)}
                      title={policy.enabled ? 'Disable the policy before deleting it.' : undefined}
                      type="button"
                    >
                      {policy.enabled
                        ? 'Disable first'
                        : deletePolicyMutation.isPending && deletePolicyMutation.variables?.policy.id === policy.id
                        ? 'Deleting…'
                        : 'Delete'}
                    </button>
                  </div>
                  <div className="policy-inline-toggle">
                    <span className="policy-inline-toggle-label">Enabled</span>
                    <button
                      className={`policy-enabled-toggle${policy.enabled ? ' active' : ''}`}
                      disabled={
                        togglePolicyMutation.isPending && togglePolicyMutation.variables?.policy.id === policy.id
                      }
                      onClick={() => void handleTogglePolicy(policy)}
                      type="button"
                    >
                      {togglePolicyMutation.isPending && togglePolicyMutation.variables?.policy.id === policy.id
                        ? 'Saving…'
                        : policy.enabled
                          ? 'true'
                          : 'false'}
                    </button>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </section>

      </div>

      <ModalDialog
        closeLabel="Close policy details"
        description={
          selectedPolicy
            ? `${currentPolicyTypeLabel} • current version ${selectedPolicy.version}`
            : undefined
        }
        dismissible={!rollbackPolicyMutation.isPending}
        eyebrow="Policy details"
        headerMeta={
          selectedPolicy && policyDetailTab === 'history' ? (
            <span className="status-pill status-pill-neutral">Retention limit 3</span>
          ) : null
        }
        closeOnEscape={!selectedComparisonVersion}
        closeOnOverlayClick={!selectedComparisonVersion}
        onClose={closeHistoryModal}
        open={isHistoryModalOpen && Boolean(selectedPolicy)}
        size="wide"
        title={selectedPolicy ? selectedPolicy.name : 'Policy details'}
      >
        {selectedPolicy ? (
          <div className="policy-history-modal">
            <div className="policy-detail-tabs" aria-label="Policy detail views">
              <button
                aria-pressed={policyDetailTab === 'overview'}
                className={`policy-detail-tab${policyDetailTab === 'overview' ? ' active' : ''}`}
                onClick={() => setPolicyDetailTab('overview')}
                type="button"
              >
                Overview
              </button>
              <button
                aria-pressed={policyDetailTab === 'history'}
                className={`policy-detail-tab${policyDetailTab === 'history' ? ' active' : ''}`}
                onClick={() => setPolicyDetailTab('history')}
                type="button"
              >
                History
              </button>
            </div>

            <section className="policy-current-card">
              <div className="policy-current-header">
                <div className="policy-list-item-badges">
                  <span className={`policy-badge ${getActionTone(selectedPolicy.action)}`}>{selectedPolicy.action}</span>
                  <span className={`policy-badge ${getEnabledTone(selectedPolicy.enabled)}`}>
                    {selectedPolicy.enabled ? 'enabled' : 'disabled'}
                  </span>
                  {isPolicyDryRun(selectedPolicy) ? (
                    <span className="policy-badge policy-badge-muted">dry run</span>
                  ) : null}
                </div>
                <div className="policy-current-actions">
                  <div className="policy-list-item-actions">
                    <button
                      className="policy-card-action policy-card-action-danger"
                      disabled={selectedPolicy.enabled || deletePolicyMutation.isPending}
                      onClick={() => void handleDeletePolicy(selectedPolicy)}
                      title={selectedPolicy.enabled ? 'Disable the policy before deleting it.' : undefined}
                      type="button"
                    >
                      {selectedPolicy.enabled
                        ? 'Disable first'
                        : deletePolicyMutation.isPending && deletePolicyMutation.variables?.policy.id === selectedPolicy.id
                        ? 'Deleting…'
                        : 'Delete'}
                    </button>
                  </div>
                  <div className="policy-inline-toggle">
                    <span className="policy-inline-toggle-label">Enabled</span>
                    <button
                      className={`policy-enabled-toggle${selectedPolicy.enabled ? ' active' : ''}`}
                      disabled={
                        togglePolicyMutation.isPending && togglePolicyMutation.variables?.policy.id === selectedPolicy.id
                      }
                      onClick={() => void handleTogglePolicy(selectedPolicy)}
                      type="button"
                    >
                      {togglePolicyMutation.isPending && togglePolicyMutation.variables?.policy.id === selectedPolicy.id
                        ? 'Saving…'
                        : selectedPolicy.enabled
                          ? 'true'
                          : 'false'}
                    </button>
                  </div>
                </div>
              </div>

              {deletePolicyMutation.isError ? (
                <div className="policy-error-panel">
                  <h4>Unable to delete policy</h4>
                  <p className="muted">{deleteErrorMessage}</p>
                </div>
              ) : null}

              <div className="policy-config-summary">
                <span className="policy-config-label">{getPolicyConfigDetail(selectedPolicy).label}</span>
                <span className="policy-config-value">{getPolicyConfigDetail(selectedPolicy).value}</span>
              </div>
              <dl className="metadata-list compact-metadata-list">
                <div>
                  <dt>Policy id</dt>
                  <dd>
                    <code>{selectedPolicy.id}</code>
                  </dd>
                </div>
                <div>
                  <dt>Scope</dt>
                  <dd>{formatPolicyScopeLabel(selectedPolicy, upstreamsByID)}</dd>
                </div>
                <div>
                  <dt>Created</dt>
                  <dd>{formatTimestamp(selectedPolicy.created_at)}</dd>
                </div>
                <div>
                  <dt>Schema</dt>
                  <dd>v{selectedPolicy.schema_version}</dd>
                </div>
                <div>
                  <dt>Priority</dt>
                  <dd>{selectedPolicy.priority}</dd>
                </div>
                <div>
                  <dt>Updated</dt>
                  <dd>{formatTimestamp(selectedPolicy.updated_at)}</dd>
                </div>
              </dl>
            </section>

            {policyDetailTab === 'overview' ? (
              <section className="policy-metadata-card">
                <h4>Configuration</h4>
                <div className="policy-config-field-list">
                  {getPolicyConfigFields(selectedPolicy).map((field) => (
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

            {policyDetailTab === 'history' ? (
              <>
                {versionsQuery.isError ? (
                  <div className="policy-error-panel">
                    <h4>Unable to load policy versions</h4>
                    <p className="muted">{versionsQuery.error.message}</p>
                  </div>
                ) : null}

                {versionsQuery.isPending ? (
                  <div className="policy-empty-state">
                    <h4>Loading history</h4>
                    <p className="muted">Pulling retained versions for this policy.</p>
                  </div>
                ) : null}

                {!versionsQuery.isPending && !versionsQuery.isError && selectedPolicyVersions.length === 0 ? (
                  <div className="policy-empty-state">
                    <h4>No retained versions yet</h4>
                    <p className="muted">
                      Version history appears after the first update or rollback snapshot is stored by the backend.
                    </p>
                  </div>
                ) : null}

                <div className="policy-history-list">
                  {selectedPolicyVersions.map((version) => (
                    <article key={version.version} className="policy-history-item">
                      <div className="policy-history-item-header">
                        <div>
                          <h4>Version {version.version}</h4>
                          <p className="muted">{formatTimestamp(version.created_at)}</p>
                        </div>
                        <div className="policy-history-actions">
                          <button className="policy-card-action" onClick={() => openPolicyDiff(version)} type="button">
                            Compare
                          </button>
                          <button
                            className="secondary-button"
                            disabled={rollbackPolicyMutation.isPending}
                            onClick={() => void handleRollback(selectedPolicy.id, version.version)}
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

                {rollbackPolicyMutation.isError ? (
                  <div className="policy-error-panel">
                    <h4>Rollback request failed</h4>
                    <p className="muted">{rollbackPolicyMutation.error.message}</p>
                  </div>
                ) : null}
              </>
            ) : null}
          </div>
        ) : null}
      </ModalDialog>

      <ModalDialog
        closeLabel="Close policy diff"
        description={
          selectedPolicy && selectedComparisonVersion
            ? `Compare retained version ${selectedComparisonVersion.version} against current version ${selectedPolicy.version} in JSON or YAML.`
            : undefined
        }
        eyebrow="Policy diff"
        headerMeta={
          selectedPolicy && selectedComparisonVersion ? (
            <>
              <span className="status-pill status-pill-neutral">Current v{selectedPolicy.version}</span>
              <span className="status-pill status-pill-neutral">Compare v{selectedComparisonVersion.version}</span>
            </>
          ) : null
        }
        onClose={closePolicyDiff}
        open={Boolean(selectedPolicy && selectedComparisonVersion)}
        size="wide"
        title={
          selectedComparisonVersion ? `Version ${selectedComparisonVersion.version} vs current` : 'Policy diff'
        }
      >
        {selectedPolicy && selectedComparisonVersion ? (
          <div className="policy-diff-modal">
            <div className="policy-preview-header">
              <div>
                <h4>Definition changes</h4>
                <p className="muted">
                  Removed lines come from the retained version. Added lines show what is in the current policy now.
                </p>
              </div>
              <div className="policy-preview-toggle" aria-label="Policy diff format">
                <button
                  aria-pressed={diffFormat === 'json'}
                  className={`policy-preview-toggle-button${diffFormat === 'json' ? ' active' : ''}`}
                  onClick={() => setDiffFormat('json')}
                  type="button"
                >
                  JSON
                </button>
                <button
                  aria-pressed={diffFormat === 'yaml'}
                  className={`policy-preview-toggle-button${diffFormat === 'yaml' ? ' active' : ''}`}
                  onClick={() => setDiffFormat('yaml')}
                  type="button"
                >
                  YAML
                </button>
              </div>
            </div>

            <div className="policy-diff-summary">
              <span className="policy-badge policy-badge-muted">Retained version {selectedComparisonVersion.version}</span>
              <span className="policy-badge policy-badge-info">Current version {selectedPolicy.version}</span>
              {!policyDiffHasChanges ? <span className="status-pill status-pill-neutral">No definition changes</span> : null}
            </div>

            <div className="policy-diff-legend" aria-hidden="true">
              <span className="policy-diff-legend-item policy-diff-legend-item-removed">Removed</span>
              <span className="policy-diff-legend-item policy-diff-legend-item-added">Added</span>
              <span className="policy-diff-legend-item">Unchanged</span>
            </div>

            <div className="policy-diff-table">
              <div className="policy-diff-table-header">
                <span>Δ</span>
                <span>Old</span>
                <span>Now</span>
                <span>{diffFormat.toUpperCase()}</span>
              </div>
              <div className="policy-diff-lines" role="table" aria-label="Policy definition diff">
                {policyDiffLines.map((line, index) => (
                  <div
                    key={`${line.type}-${line.oldLineNumber ?? 'new'}-${line.newLineNumber ?? 'old'}-${index}`}
                    className={`policy-diff-row policy-diff-row-${line.type}`}
                    role="row"
                  >
                    <span className="policy-diff-marker" aria-hidden="true">
                      {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
                    </span>
                    <span className="policy-diff-line-number">{line.oldLineNumber ?? ''}</span>
                    <span className="policy-diff-line-number">{line.newLineNumber ?? ''}</span>
                    <code className="policy-diff-content">{line.content === '' ? ' ' : line.content}</code>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </ModalDialog>

      <ModalWizard
        allowStepSelection
        aside={
          <div className="policy-preview-column">
            <section className="policy-preview-card">
              <div className="policy-preview-header">
                <div>
                  <h4>Policy preview</h4>
                  <p className="muted">Preview the current draft in JSON or YAML.</p>
                </div>
                <div className="policy-preview-toggle" aria-label="Policy preview format">
                  <button
                    aria-pressed={previewFormat === 'json'}
                    className={`policy-preview-toggle-button${previewFormat === 'json' ? ' active' : ''}`}
                    onClick={() => setPreviewFormat('json')}
                    type="button"
                  >
                    JSON
                  </button>
                  <button
                    aria-pressed={previewFormat === 'yaml'}
                    className={`policy-preview-toggle-button${previewFormat === 'yaml' ? ' active' : ''}`}
                    onClick={() => setPreviewFormat('yaml')}
                    type="button"
                  >
                    YAML
                  </button>
                </div>
              </div>
              <pre className="code-block policy-preview-block">
                {previewFormat === 'json' ? jsonPreview : yamlPreview}
              </pre>
            </section>
          </div>
        }
        currentStep={wizardStep}
        description={
          isEditingPolicy
            ? 'Edit the policy in guided steps.'
            : 'Create the policy in guided steps.'
        }
        dismissible={!savePolicyMutation.isPending}
        eyebrow="Guided creation"
        footer={
          <div className="wizard-actions wizard-actions-modal">
            <button
              className="secondary-button"
              disabled={wizardStep === 0}
              onClick={() => {
                setDraftFieldErrors({})
                setWizardStep((currentStep) => Math.max(currentStep - 1, 0))
              }}
              type="button"
            >
              Back
            </button>
            <div className="wizard-actions-right">
              <button className="secondary-button" onClick={resetCurrentDraft} type="button">
                {isEditingPolicy ? 'Reset changes' : 'Discard draft'}
              </button>
              {wizardStep === policyWizardSteps.length - 1 ? (
                <button
                  className="primary-button"
                  disabled={reviewErrors.length > 0 || savePolicyMutation.isPending}
                  onClick={() => void handleSavePolicy()}
                  type="button"
                >
                  {savePolicyMutation.isPending
                    ? isEditingPolicy
                      ? 'Saving changes…'
                      : 'Creating policy…'
                    : isEditingPolicy
                      ? 'Save changes'
                      : 'Create policy'}
                </button>
              ) : (
                <button
                  className="primary-button"
                  disabled={!canAdvanceWizard}
                  onClick={handleWizardNext}
                  type="button"
                >
                  Next
                </button>
              )}
            </div>
          </div>
        }
        headerMeta={
          <>
            {tenantId ? <span className="status-pill status-pill-neutral">Tenant scoped</span> : null}
            {isEditingPolicy ? <span className="status-pill status-pill-neutral">Editing</span> : null}
            {draft.type ? <span className="policy-badge policy-badge-info">{draft.type}</span> : null}
            {policyTypesQuery.isError ? (
              <span className="status-pill status-pill-neutral">Fallback metadata</span>
            ) : null}
          </>
        }
        onClose={closeCreateModal}
        onStepChange={handleWizardStepChange}
        open={isCreateModalOpen}
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
                <p className="eyebrow">Guided-first flow</p>
                <h3>{currentPolicyWizardStep?.label}</h3>
                {currentPolicyWizardStep?.description ? (
                  <p className="muted">{currentPolicyWizardStep.description}</p>
                ) : null}
              </div>
              <span className="policy-preview-note">{previewFormat.toUpperCase()} preview</span>
            </div>
          </div>

          {wizardStep === 0 ? (
            <div className="policy-form-stack">
              {upstreams.length > 0 ? (
                <section className="policy-summary-card">
                  <h4>Choose the upstream scope first</h4>
                  <p className="muted">Policy types depend on the selected upstream.</p>
                </section>
              ) : null}

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
                    const compatibleDescriptorsForUpstream =
                      compatiblePolicyTypesByUpstream.get(upstream.id) ?? []
                  return (
                    <button
                      key={upstream.id}
                      className={`policy-type-card${isSelected ? ' selected' : ''}`}
                      onClick={() => handleUpstreamSelect(upstream.id)}
                      type="button"
                    >
                      <div className="policy-type-card-header">
                        <strong>{upstream.name}</strong>
                        <span className="policy-badge policy-badge-info">{upstream.ecosystem.toUpperCase()}</span>
                      </div>
                      <p className="muted">{upstream.base_url}</p>
                      <p className="policy-type-card-note">
                        {compatibleDescriptorsForUpstream.length > 0
                          ? `${compatibleDescriptorsForUpstream.length} compatible policy type${compatibleDescriptorsForUpstream.length === 1 ? '' : 's'} available for this upstream.`
                          : 'No compatible policy types are currently available for this upstream.'}
                      </p>
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

              {upstreamsQuery.isError ? (
                <section className="policy-error-panel">
                  <h4>Unable to load upstreams</h4>
                  <p className="muted">{upstreamsQuery.error.message}</p>
                </section>
              ) : null}

              {!upstreamsQuery.isPending && upstreams.length === 0 ? (
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

          {wizardStep === 1 ? (
            <div className="policy-form-stack">
              {selectedUpstream ? (
                <section className="policy-summary-card">
                  <h4>{selectedUpstream.name} policy catalog</h4>
                  <p className="muted">
                    Showing policy types that match this {selectedUpstream.ecosystem.toUpperCase()} upstream.
                  </p>
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
                    const isSelected = descriptor.type === draft.type
                    const supportedActions = getSupportedActions(descriptor.type as PolicyType, descriptor)

                    return (
                      <button
                        key={descriptor.type}
                        className={`policy-type-card${isSelected ? ' selected' : ''}`}
                        onClick={() => handleTypeSelect(descriptor.type as PolicyType)}
                        type="button"
                      >
                        <div className="policy-type-card-header">
                          <strong>{getPolicyTypeLabel(descriptor.type as PolicyType)}</strong>
                          <span className="policy-badge policy-badge-info">{descriptor.type}</span>
                        </div>
                        <p className="muted">{descriptor.summary}</p>
                        <p className="policy-type-card-note">Available for the selected upstream.</p>
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

          {wizardStep === 2 && draft.type && selectedDescriptor && selectedDefinition && selectedUpstream ? (
            <div className="policy-form-grid">
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
                  onChange={(event) => updateDraft('name', event.target.value)}
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
                  onChange={(event) => updateDraft('action', event.target.value as PolicyDraftState['action'])}
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
                  onChange={(event) => updateDraft('priority', event.target.value)}
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
                  onChange={(event) => updateDraft('schemaVersion', event.target.value)}
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
                  onChange={(event) => updateDraft('enabled', event.target.checked)}
                  type="checkbox"
                />
                <span>Policy is enabled</span>
              </label>

            </div>
          ) : null}

          {wizardStep === 3 && draft.type && selectedDescriptor && selectedDefinition ? (
            <div className="policy-form-stack">
              {selectedDefinition.numberField ? (
                <label className={`policy-field${draftFieldErrors.numericValue ? ' policy-field-invalid' : ''}`}>
                  <span>{selectedDefinition.numberLabel}</span>
                  <input
                    aria-invalid={Boolean(draftFieldErrors.numericValue)}
                    min={selectedDefinition.numberMin}
                    onChange={(event) => updateDraft('numericValue', event.target.value)}
                    placeholder={
                      selectedDefinition.numberDefault === undefined
                        ? ''
                        : String(selectedDefinition.numberDefault)
                    }
                    step={selectedDefinition.numberStep}
                    type="number"
                    value={draft.numericValue}
                  />
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
                    onChange={(event) => updateDraft('listValue', event.target.value)}
                    placeholder={selectedDefinition.listPlaceholder}
                    rows={4}
                    value={draft.listValue}
                  />
                  <small>Enter one value per line or separate items with commas.</small>
                  {draftFieldErrors.listValue ? (
                    <p className="policy-field-error">{draftFieldErrors.listValue}</p>
                  ) : null}
                </label>
              ) : null}

              {selectedDefinition.supportsExcludePackages ? (
                <label className="policy-field">
                  <span>Exclude packages</span>
                  <textarea
                    onChange={(event) => updateDraft('excludePackages', event.target.value)}
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
                        updateDraft(
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
                        updateDraft(
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

              <label className="policy-field checkbox-field">
                <input
                  checked={draft.dryRun}
                  onChange={(event) => updateDraft('dryRun', event.target.checked)}
                  type="checkbox"
                />
                <span>Record matches as dry-run warnings instead of denying immediately</span>
              </label>

              <section className="policy-metadata-card">
                <h4>Policy type guidance</h4>
                <p className="muted">{selectedDescriptor.description}</p>
                <p className="muted">{selectedDescriptor.help}</p>
                <p className="muted">
                  Supported ecosystems:{' '}
                  {getSupportedEcosystems(selectedDescriptor)
                    .map((ecosystem) => ecosystem.toUpperCase())
                    .join(', ')}
                  {getRequiredCapabilities(selectedDescriptor).length > 0
                    ? ` • Requires ${getRequiredCapabilities(selectedDescriptor)
                        .map((capability) => formatUpstreamCapabilityLabel(capability))
                        .join(', ')}`
                    : ''}
                </p>
                <pre className="code-block policy-example-block">{selectedDescriptor.example}</pre>
              </section>
            </div>
          ) : null}

          {wizardStep === 4 ? (
            <div className="policy-review-stack">
              <section className="policy-summary-card">
                <h4>Review before {isEditingPolicy ? 'saving' : 'creating'}</h4>
                <p className="muted">Confirm the draft, then save.</p>
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

              {savePolicyMutation.isError ? (
                <section className="policy-error-panel">
                  <h4>Unable to save policy</h4>
                  <p className="muted">{savePolicyMutation.error.message}</p>
                </section>
              ) : null}
            </div>
          ) : null}
        </div>
      </ModalWizard>
    </section>
  )
}
