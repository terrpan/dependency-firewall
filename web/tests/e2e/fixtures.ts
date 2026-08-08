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
    if (path.endsWith('/upstreams')) return route.fulfill({ json: [{ id: 'npm', name: 'npm registry', url: 'https://registry.npmjs.org', enabled: true }] })
    if (path.endsWith('/policies/types')) return route.fulfill({ json: [] })
    if (path.endsWith('/policies')) return route.fulfill({ json: [] })
    if (path.includes('/dependency-graphs')) return route.fulfill({ json: [] })
    return route.fulfill({ json: {} })
  })
}

export const test = base
export { expect }
