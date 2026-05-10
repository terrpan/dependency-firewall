import {
  createEmptyUpstreamDraft,
  upstreamBaseUrlExamples,
  type UpstreamCapability,
  type UpstreamDraft,
  type UpstreamEcosystem,
} from './api.ts'

export function updateUpstreamDraftField(
  draft: UpstreamDraft,
  field: keyof UpstreamDraft,
  value: string,
): UpstreamDraft {
  if (field !== 'ecosystem') {
    return {
      ...draft,
      [field]: value,
    }
  }

  const nextEcosystem = value as UpstreamEcosystem
  const currentBaseUrl = draft.baseUrl.trim()
  const shouldUseExample =
    !currentBaseUrl || currentBaseUrl === upstreamBaseUrlExamples[draft.ecosystem]

  return {
    ...draft,
    ecosystem: nextEcosystem,
    baseUrl: shouldUseExample ? upstreamBaseUrlExamples[nextEcosystem] : draft.baseUrl,
    capabilities: createEmptyUpstreamDraft(nextEcosystem).capabilities,
    ...(nextEcosystem === 'oci'
      ? {}
      : {
          authType: 'none' as const,
          authUsername: '',
          authPassword: '',
          authToken: '',
        }),
  }
}

export function toggleUpstreamDraftCapability(
  draft: UpstreamDraft,
  capability: UpstreamCapability,
  checked: boolean,
): UpstreamDraft {
  const nextCapabilities = checked
    ? [...draft.capabilities.filter((currentCapability) => currentCapability !== capability), capability]
    : draft.capabilities.filter((currentCapability) => currentCapability !== capability)

  return {
    ...draft,
    capabilities: nextCapabilities,
  }
}
