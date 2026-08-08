import { test as base, expect, type Page } from '@playwright/test'

export type AuthState = 'anonymous' | 'authenticated' | 'unauthorized' | 'expired'

export async function installAuth(page: Page, state: AuthState = 'authenticated') {
  await page.addInitScript((nextState) => {
    window.__DEPENDENCY_FIREWALL_TEST_AUTH__ = { state: nextState, token: 'playwright-access-token' }
    localStorage.setItem('dependency-firewall-theme', 'light')
  }, state)
}

export const policyOverviewFixtures = [
  {
    id: 'policy-blocklist', tenant_id: 'tenant-acme', upstream_id: 'npm', name: 'Block untrusted namespaces',
    type: 'blocklist', action: 'deny', schema_version: 1, config: { namespaces: ['untrusted', 'legacy-vendor'] },
    target: { dependency_scope: ['direct', 'transitive'], dependency_types: ['prod'], on_unknown: 'warn' },
    priority: 10, enabled: true, version: 3, created_at: '2026-07-01T10:00:00Z', updated_at: '2026-08-08T10:00:00Z',
  },
  {
    id: 'policy-licenses', tenant_id: 'tenant-acme', upstream_id: 'npm', name: 'Approved licenses',
    type: 'license_allowlist', action: 'deny', schema_version: 2,
    config: { licenses: ['MIT', 'Apache-2.0', 'BSD-3-Clause'], unlicensed_behavior: 'deny', unavailable_metadata_behavior: 'skip', dry_run: true },
    priority: 20, enabled: true, version: 2, created_at: '2026-07-03T10:00:00Z', updated_at: '2026-08-07T10:00:00Z',
  },
  {
    id: 'policy-age', tenant_id: 'tenant-acme', upstream_id: 'npm', name: 'Package cooling-off period',
    type: 'minimum_age', action: 'deny', schema_version: 1,
    config: { min_age_days: 7, exclude_packages: ['@acme/release-tools'] },
    priority: 30, enabled: false, version: 1, created_at: '2026-08-01T10:00:00Z', updated_at: '2026-08-06T10:00:00Z',
  },
] as const

export const tenantOverviewFixtures = [
  {
    id: 'tenant-acme',
    name: 'Acme Engineering',
    created_at: '2026-08-01T10:00:00Z',
    updated_at: '2026-08-08T10:00:00Z',
  },
  {
    id: 'tenant-platform',
    name: 'Platform Engineering',
    created_at: '2026-07-15T10:00:00Z',
    updated_at: '2026-08-07T10:00:00Z',
  },
] as const

type ApiFixtureOptions = {
  policies?: readonly unknown[]
  tenantListFailures?: number
  tenants?: readonly Record<string, unknown>[]
}

export async function installApi(page: Page, options: ApiFixtureOptions = {}) {
  const tenantFixtures: Array<Record<string, unknown>> = (options.tenants ?? tenantOverviewFixtures.slice(0, 1))
    .map((tenant) => ({ ...tenant }))
  let remainingTenantListFailures = options.tenantListFailures ?? 0

  await page.route('**/healthz', route => route.fulfill({ json: { status: 'ok', dependencies: {} } }))
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/tenants') && route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as { name?: string }
      const tenant = {
        id: 'tenant-platform-new',
        name: body.name?.trim() || 'Platform Engineering',
        created_at: '2026-08-08T10:00:00Z',
        updated_at: '2026-08-08T10:00:00Z',
      }
      tenantFixtures.push(tenant)
      return route.fulfill({ json: tenant })
    }
    if (path.endsWith('/tenants')) {
      if (remainingTenantListFailures > 0) {
        remainingTenantListFailures -= 1
        return route.fulfill({ status: 503, json: { error: 'tenant inventory unavailable' } })
      }
      return route.fulfill({ json: tenantFixtures })
    }
    if (path.endsWith('/evaluations')) return route.fulfill({ json: [{
      id: 'evaluation-react',
      artifact: { ecosystem: 'npm', name: 'react', version: '19.2.0' },
      outcome: 'deny',
      policy_id: 'policy-blocklist',
      policy_hash: 'policyhash123',
      reason: 'Namespace matched the tenant blocklist.',
      reasons: [{ action: 'deny', category: 'blocklist', message: 'Namespace matched the tenant blocklist.', policy_id: 'policy-blocklist', policy_name: 'Protected namespaces' }],
      warnings: [],
      evaluated_at: '2026-08-08T10:00:00Z',
    }] })
    if (path.endsWith('/upstreams') && route.request().method() === 'POST') return route.fulfill({ json: { id: 'npm-internal', tenant_id: 'tenant-acme', name: 'Internal npm', ecosystem: 'npm', base_url: 'https://npm.example.test', capabilities: ['publish_time'], auth_type: 'none', created_at: '2026-08-08T10:00:00Z', updated_at: '2026-08-08T10:00:00Z' } })
    if (path.endsWith('/upstreams')) return route.fulfill({ json: [{ id: 'npm', tenant_id: 'tenant-acme', name: 'npm registry', ecosystem: 'npm', base_url: 'https://registry.npmjs.org', capabilities: ['publish_time', 'licenses'], auth_type: 'none', created_at: '2026-08-01T10:00:00Z', updated_at: '2026-08-08T10:00:00Z' }] })
    if (path.endsWith('/policy-types')) return route.fulfill({ json: [{ type: 'blocklist', summary: 'Block selected namespaces.', description: 'Deny packages from explicitly blocked namespaces.', help: 'Add one namespace per line.', example: 'namespaces: [blocked]', supported_actions: ['deny', 'allow'], supported_schema_versions: [1], current_schema_version: 1, supported_ecosystems: ['npm', 'oci'], required_capabilities: [] }] })
    if (path.endsWith('/policies')) return route.fulfill({ json: options.policies ?? [] })
    if (path.endsWith('/dependency-graphs/root-react')) return route.fulfill({ json: {
      root: { id: 'root-react', tenant_id: 'tenant-acme', upstream_id: 'npm', package_name: 'react-app', version: '1.0.0', status: 'complete', graph_hash: 'abc123def456', created_at: '2026-08-08T10:00:00Z', updated_at: '2026-08-08T10:00:00Z', resolved_at: '2026-08-08T10:00:00Z' },
      nodes: [
        { id: 'node-root', artifact: { ecosystem: 'npm', name: 'react-app', version: '1.0.0' }, min_depth: 0, dependency_types: ['prod'] },
        { id: 'node-react', artifact: { ecosystem: 'npm', name: 'react', version: '19.2.0' }, min_depth: 1, dependency_types: ['prod'] },
        { id: 'node-scheduler', artifact: { ecosystem: 'npm', name: 'scheduler', version: '0.27.0' }, min_depth: 2, dependency_types: ['prod'] },
      ],
      edges: [
        { id: 'edge-react', parent_node_id: 'node-root', child_node_id: 'node-react', dependency_type: 'prod' },
        { id: 'edge-scheduler', parent_node_id: 'node-react', child_node_id: 'node-scheduler', dependency_type: 'prod' },
      ],
    } })
    if (path.endsWith('/dependency-graphs')) return route.fulfill({ json: [{ id: 'root-react', tenant_id: 'tenant-acme', upstream_id: 'npm', package_name: 'react-app', version: '1.0.0', status: 'complete', graph_hash: 'abc123def456', created_at: '2026-08-08T10:00:00Z', updated_at: '2026-08-08T10:00:00Z', resolved_at: '2026-08-08T10:00:00Z' }] })
    return route.fulfill({ json: {} })
  })
}

export const test = base
export { expect }
