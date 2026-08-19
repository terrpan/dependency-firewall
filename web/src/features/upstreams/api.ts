import type {
  ControlPlaneApi,
  CreateUpstreamRequest,
  PolicyType,
  PolicyTypeDescriptor,
  Upstream,
} from '../../lib/api/index.ts'

export const upstreamEcosystems = ['npm', 'oci'] as const

export type UpstreamEcosystem = (typeof upstreamEcosystems)[number]
export type UpstreamCapability = NonNullable<CreateUpstreamRequest['capabilities']>[number]
export type UpstreamAuthType = 'none' | 'basic' | 'bearer_token'

type UpstreamCapabilityDefinition = {
  id: UpstreamCapability
  label: string
  description: string
}

type UpstreamEcosystemDefinition = {
  capabilities: readonly UpstreamCapabilityDefinition[]
  authTypes: readonly UpstreamAuthType[]
}

const upstreamEcosystemDefinitions: Record<UpstreamEcosystem, UpstreamEcosystemDefinition> = {
  npm: {
    authTypes: ['none'],
    capabilities: [
      {
        id: 'publish_time',
        label: 'Publish time',
        description: 'Enable age-based policies that rely on package publish timestamps.',
      },
      {
        id: 'licenses',
        label: 'Licenses',
        description: 'Enable license match and license allowlist policies.',
      },
      {
        id: 'vulnerability_lookup',
        label: 'Vulnerability lookup',
        description: 'Enable CVSS threshold policies backed by the current enrichment flow.',
      },
      {
        id: 'scorecard_lookup',
        label: 'Scorecard lookup',
        description: 'Enable OpenSSF Scorecard policies backed by npm source-repository enrichment.',
      },
    ],
  },
  oci: {
    authTypes: ['none', 'basic', 'bearer_token'],
    capabilities: [
      {
        id: 'manifest_digest_lookup',
        label: 'Manifest digest lookup',
        description: 'Enable mutable-tag blocking by resolving tags to OCI manifests and digests.',
      },
    ],
  },
}

const capabilityLabels = Object.values(upstreamEcosystemDefinitions)
  .flatMap((definition) => definition.capabilities)
  .reduce<Record<string, string>>((labels, definition) => {
    labels[definition.id] = definition.label
    return labels
  }, {})

export type UpstreamDraft = {
  name: string
  ecosystem: UpstreamEcosystem
  baseUrl: string
  capabilities: UpstreamCapability[]
  authType: UpstreamAuthType
  authUsername: string
  authPassword: string
  authToken: string
}

export type UpstreamDraftErrors = Partial<Record<keyof UpstreamDraft, string>>

export const upstreamBaseUrlExamples: Record<UpstreamEcosystem, string> = {
  npm: 'https://registry.npmjs.org',
  oci: 'https://registry-1.docker.io',
}

export const upstreamNameExamples: Record<UpstreamEcosystem, string> = {
  npm: 'npm-registry',
  oci: 'docker-hub',
}

type UpstreamsApi = Pick<ControlPlaneApi, 'upstreams'>

export function upstreamsQueryKey(tenantId: string | null) {
  return ['upstreams', tenantId] as const
}

export function createEmptyUpstreamDraft(ecosystem: UpstreamEcosystem = 'npm'): UpstreamDraft {
  return {
    name: '',
    ecosystem,
    baseUrl: upstreamBaseUrlExamples[ecosystem],
    capabilities: defaultUpstreamCapabilities(ecosystem),
    authType: 'none',
    authUsername: '',
    authPassword: '',
    authToken: '',
  }
}

export function listUpstreams(api: UpstreamsApi, tenantId: string, signal?: AbortSignal): Promise<Upstream[]> {
  return api.upstreams.list({ tenantId, signal })
}

export function createUpstream(api: UpstreamsApi, tenantId: string, body: CreateUpstreamRequest): Promise<Upstream> {
  return api.upstreams.create(body, { tenantId })
}

function isUpstreamEcosystem(value: string): value is UpstreamEcosystem {
  return upstreamEcosystems.includes(value as UpstreamEcosystem)
}

export function getUpstreamCapabilityDefinitions(ecosystem: UpstreamEcosystem) {
  return upstreamEcosystemDefinitions[ecosystem].capabilities
}

export function getUpstreamAuthTypes(ecosystem: UpstreamEcosystem): readonly UpstreamAuthType[] {
  return upstreamEcosystemDefinitions[ecosystem].authTypes
}

export function upstreamEcosystemSupportsAuth(ecosystem: UpstreamEcosystem): boolean {
  return getUpstreamAuthTypes(ecosystem).some((authType) => authType !== 'none')
}

export function upstreamEcosystemSupportsAuthType(ecosystem: UpstreamEcosystem, authType: UpstreamAuthType): boolean {
  return getUpstreamAuthTypes(ecosystem).includes(authType)
}

export function defaultUpstreamCapabilities(ecosystem: UpstreamEcosystem): UpstreamCapability[] {
  return getUpstreamCapabilityDefinitions(ecosystem).map((definition) => definition.id)
}

export function normalizeUpstreamCapabilities(
  ecosystem: UpstreamEcosystem,
  capabilities: readonly string[] | null | undefined,
): UpstreamCapability[] {
  const selected = new Set(capabilities ?? [])
  return getUpstreamCapabilityDefinitions(ecosystem)
    .filter((definition) => selected.has(definition.id))
    .map((definition) => definition.id)
}

export function formatUpstreamCapabilityLabel(capability: string): string {
  return capabilityLabels[capability] ?? capability
}

export function listSupportedPolicyTypes(upstream: Upstream): string[] {
  return upstream.supported_policy_types ?? []
}

function getDescriptorSupportedEcosystems(descriptor: PolicyTypeDescriptor): UpstreamEcosystem[] {
  const supportedEcosystems = descriptor.supported_ecosystems ?? []
  if (supportedEcosystems.length === 0) {
    return [...upstreamEcosystems]
  }

  return supportedEcosystems.filter(isUpstreamEcosystem)
}

function getDescriptorRequiredCapabilities(descriptor: PolicyTypeDescriptor): UpstreamCapability[] {
  const requiredCapabilities = descriptor.required_capabilities ?? []
  return requiredCapabilities.filter((capability: string): capability is UpstreamCapability =>
    getUpstreamCapabilityDefinitions('npm')
      .concat(getUpstreamCapabilityDefinitions('oci'))
      .some((definition) => definition.id === capability),
  )
}

export function upstreamSupportsPolicyType(
  upstream: Upstream,
  policyType: PolicyType,
  descriptor?: PolicyTypeDescriptor | null,
): boolean {
  const supportedPolicyTypes = listSupportedPolicyTypes(upstream)
  if (supportedPolicyTypes.length > 0) {
    return supportedPolicyTypes.includes(policyType)
  }

  if (!descriptor || !isUpstreamEcosystem(upstream.ecosystem)) {
    return false
  }

  if (!getDescriptorSupportedEcosystems(descriptor).includes(upstream.ecosystem)) {
    return false
  }

  const supportedCapabilities = new Set(normalizeUpstreamCapabilities(upstream.ecosystem, upstream.capabilities))
  return getDescriptorRequiredCapabilities(descriptor).every((capability) => supportedCapabilities.has(capability))
}

export function validateUpstreamDraft(draft: UpstreamDraft): {
  value: CreateUpstreamRequest | null
  errors: UpstreamDraftErrors
} {
  const name = draft.name.trim()
  const ecosystem = draft.ecosystem.trim()
  const baseUrl = draft.baseUrl.trim()
  const capabilities = normalizeUpstreamCapabilities(draft.ecosystem, draft.capabilities)
  const errors: UpstreamDraftErrors = {}
  const authUsername = draft.authUsername.trim()
  const authPassword = draft.authPassword.trim()
  const authToken = draft.authToken.trim()

  if (!name) {
    errors.name = 'Enter a display name for this upstream.'
  }

  if (!isUpstreamEcosystem(ecosystem)) {
    errors.ecosystem = 'Choose either npm or OCI.'
  }

  if (!baseUrl) {
    errors.baseUrl = 'Enter the upstream base URL.'
  } else {
    try {
      const url = new URL(baseUrl)
      if (!['http:', 'https:'].includes(url.protocol)) {
        errors.baseUrl = 'Use an http or https URL.'
      }
    } catch {
      errors.baseUrl = 'Enter a valid URL.'
    }
  }

  if (Object.keys(errors).length > 0) {
    return { value: null, errors }
  }

  if (!upstreamEcosystemSupportsAuthType(draft.ecosystem, draft.authType)) {
    errors.authType = 'Choose an authentication type supported by this ecosystem.'
  }

  if (upstreamEcosystemSupportsAuthType(draft.ecosystem, 'basic') && draft.authType === 'basic') {
    if (!authUsername) {
      errors.authUsername = 'Enter the registry username.'
    }
    if (!authPassword) {
      errors.authPassword = 'Enter the registry password or token.'
    }
  }

  if (
    upstreamEcosystemSupportsAuthType(draft.ecosystem, 'bearer_token') &&
    draft.authType === 'bearer_token' &&
    !authToken
  ) {
    errors.authToken = 'Enter the bearer token.'
  }

  if (Object.keys(errors).length > 0) {
    return { value: null, errors }
  }

  const auth =
    upstreamEcosystemSupportsAuthType(draft.ecosystem, draft.authType) && draft.authType !== 'none'
      ? draft.authType === 'basic'
        ? { type: 'basic' as const, username: authUsername, password: authPassword }
        : { type: 'bearer_token' as const, token: authToken }
      : undefined

  return {
    value: {
      name,
      ecosystem,
      base_url: baseUrl,
      capabilities,
      ...(auth ? { auth } : {}),
    },
    errors: {},
  }
}

export function sortUpstreams(upstreams: readonly Upstream[]): Upstream[] {
  return [...upstreams].sort(
    (left, right) => left.ecosystem.localeCompare(right.ecosystem) || left.name.localeCompare(right.name),
  )
}
