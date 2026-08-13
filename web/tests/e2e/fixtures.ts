import { test as base, expect, type Page } from '@playwright/test'

export type AuthState = 'anonymous' | 'authenticated' | 'unauthorized' | 'expired'

export async function installAuth(page: Page, state: AuthState = 'authenticated') {
  await page.addInitScript((nextState) => {
    window.__DEPENDENCY_FIREWALL_TEST_AUTH__ = { state: nextState, token: 'playwright-access-token' }
    localStorage.setItem('dependency-firewall-theme', 'light')
  }, state)
}

export async function installApi(page: Page) {
  await page.route('**/healthz', route => route.fulfill({ json: { status: 'ok', dependencies: {} } }))
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/tenants') && route.request().method() === 'POST') return route.fulfill({ json: { id: 'tenant-platform', name: 'Platform Engineering', created_at: '2026-08-08T10:00:00Z', updated_at: '2026-08-08T10:00:00Z' } })
    if (path.endsWith('/tenants')) return route.fulfill({ json: [{ id: 'tenant-acme', name: 'Acme Engineering', created_at: '2026-08-01T10:00:00Z', updated_at: '2026-08-08T10:00:00Z' }] })
    if (path.endsWith('/evaluations')) return route.fulfill({ json: [] })
    if (path.endsWith('/upstreams') && route.request().method() === 'POST') return route.fulfill({ json: { id: 'npm-internal', tenant_id: 'tenant-acme', name: 'Internal npm', ecosystem: 'npm', base_url: 'https://npm.example.test', capabilities: ['publish_time'], auth_type: 'none', created_at: '2026-08-08T10:00:00Z', updated_at: '2026-08-08T10:00:00Z' } })
    if (path.endsWith('/upstreams')) return route.fulfill({ json: [{ id: 'npm', tenant_id: 'tenant-acme', name: 'npm registry', ecosystem: 'npm', base_url: 'https://registry.npmjs.org', capabilities: ['publish_time', 'licenses'], auth_type: 'none', created_at: '2026-08-01T10:00:00Z', updated_at: '2026-08-08T10:00:00Z' }] })
    if (path.endsWith('/policy-types')) return route.fulfill({ json: [{ type: 'blocklist', summary: 'Block selected namespaces.', description: 'Deny packages from explicitly blocked namespaces.', help: 'Add one namespace per line.', example: 'namespaces: [blocked]', supported_actions: ['deny', 'allow'], supported_schema_versions: [1], current_schema_version: 1, supported_ecosystems: ['npm', 'oci'], required_capabilities: [] }] })
    if (path.endsWith('/policies')) return route.fulfill({ json: [] })
    if (path.includes('/dependency-graphs')) return route.fulfill({ json: [] })
    return route.fulfill({ json: {} })
  })
}

export const test = base
export { expect }
