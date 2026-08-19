import { dependencyGraphRootFixtures, expect, installApi, installAuth, test } from './fixtures'

test.beforeEach(async ({ page }) => {
  await installAuth(page)
})

test('graph inventory defaults to a resolved root and explains failed roots', async ({ page }) => {
  const failedRoot = {
    id: 'root-failed',
    tenant_id: 'tenant-acme',
    upstream_id: 'npm',
    package_name: 'legacy-app',
    version: '2.0.0',
    status: 'failed',
    error: 'Package manifest could not be resolved.',
    created_at: '2026-08-08T09:00:00Z',
    updated_at: '2026-08-08T09:02:00Z',
  }
  await installApi(page, { dependencyGraphRoots: [failedRoot, ...dependencyGraphRootFixtures] })
  await page.goto('/dependency-graphs')

  await expect(page.getByText('Trace which packages Acme Engineering installs directly')).toBeVisible()
  const roots = page.getByRole('group', { name: 'Observed install roots' })
  const resolved = roots.getByRole('button', { name: /react-app@1.0.0/ })
  const failed = roots.getByRole('button', { name: /legacy-app@2.0.0/ })
  await expect(resolved).toHaveAttribute('aria-pressed', 'true')
  await expect(failed).toContainText('Package manifest could not be resolved.')
  await expect(page.getByRole('heading', { name: 'react-app@1.0.0' })).toBeVisible()

  await failed.click()
  await expect(failed).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByText('Selected graph unavailable')).toBeVisible()
})

test('graph technical metadata stays behind progressive disclosure', async ({ page }) => {
  await installApi(page)
  await page.goto('/dependency-graphs')

  await expect(page.getByText('abc123def456', { exact: true })).not.toBeVisible()
  await page.getByText('Technical graph details').click()
  await expect(page.getByText('abc123def456', { exact: true })).toBeVisible()
  await expect(page.getByText('root-react', { exact: true })).toBeVisible()
})

test('empty and failed graph inventories offer direct recovery', async ({ page }) => {
  await installApi(page, { dependencyGraphListFailures: 2, dependencyGraphRoots: [] })
  await page.goto('/dependency-graphs')

  await expect(page.getByText('Unable to load dependency graphs')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Refresh' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Retry' }).click()
  await expect(page.getByText('No dependency graphs yet')).toBeVisible()
  await expect(
    page.getByText('Graphs appear automatically after an npm client routes an install through Dependency Firewall'),
  ).toBeVisible()
})
