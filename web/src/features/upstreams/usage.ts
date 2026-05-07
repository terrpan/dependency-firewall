import type { Upstream } from '../../lib/api/types.ts'
import { joinUrlPath } from '../../lib/config.ts'

export type UpstreamUsageGuide = {
  title: string
  summary: string
  primaryLabel: string
  primaryCode: string
  secondaryLabel: string
  secondaryCode: string
  note: string
}

export function buildUpstreamUsageGuide(
  upstream: Upstream,
  tenantId: string | null,
  firewallRootUrl: string,
): UpstreamUsageGuide {
  const firewallURL = new URL(firewallRootUrl)

  if (upstream.ecosystem === 'npm') {
    const registryUrl = joinUrlPath(
      firewallRootUrl,
      `/npm/t/${tenantId ?? '<tenant-id>'}/u/${upstream.id}/`,
    )
    return {
      title: 'Use with npm',
      summary: 'Point npm at this upstream-specific firewall route so installs resolve through the selected upstream.',
      primaryLabel: '.npmrc',
      primaryCode: `registry=${registryUrl}`,
      secondaryLabel: 'Install command',
      secondaryCode: `npm install lodash --registry ${registryUrl}`,
      note: tenantId
        ? `This route is pinned to upstream ${upstream.id} under /npm/t/${tenantId}/u/${upstream.id}/.`
        : 'Select a tenant to render the upstream-specific npm route.',
    }
  }

  const firewallHost = firewallURL.host
  const upstreamHost = tenantId
    ? `u-${upstream.id}.${tenantId}.${firewallHost}`
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
      ? `This hostname is pinned to upstream ${upstream.id} as u-${upstream.id}.${tenantId}.${firewallHost}.`
      : 'Select a tenant to render the upstream-specific registry hostname.',
  }
}
