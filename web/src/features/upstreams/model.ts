import type { Upstream } from '../../lib/api/types.ts'
import { formatUpstreamCapabilityLabel, listSupportedPolicyTypes } from './api.ts'

const dateFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

export function formatPolicyTypeName(value: string): string {
  return value.replaceAll('_', ' ')
}

export function formatUpstreamTimestamp(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return value
  }

  return dateFormatter.format(parsed)
}

export function formatUpstreamCapabilities(upstream: Upstream | null): string[] {
  return upstream
    ? (upstream.capabilities ?? []).map((capability) => formatUpstreamCapabilityLabel(capability))
    : []
}

export function formatUpstreamPolicyTypes(upstream: Upstream | null): string[] {
  return upstream ? listSupportedPolicyTypes(upstream).map(formatPolicyTypeName) : []
}
