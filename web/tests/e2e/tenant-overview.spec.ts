import { expect, installApi, installAuth, tenantOverviewFixtures, test } from './fixtures'

test.beforeEach(async ({ page }) => {
  await installAuth(page)
})

test('makes the active workspace and tenant switching explicit', async ({ page }) => {
  await installApi(page, { tenants: tenantOverviewFixtures })
  await page.goto('/tenants')

  await expect(page.getByText('Choose which tenant to operate in. Upstreams, policies, decisions, and dependency graphs stay inside that workspace.')).toBeVisible()
  const list = page.getByRole('list', { name: 'Tenant workspaces' })
  const acme = list.getByRole('listitem').filter({ hasText: 'Acme Engineering' })
  const platform = list.getByRole('listitem').filter({ hasText: 'Platform Engineering' })

  await expect(acme).toContainText('Active workspace')
  await expect(acme.getByRole('link', { name: 'Open dashboard' })).toHaveAttribute('href', '/')
  await expect(platform.getByRole('button', { name: 'Switch to Platform Engineering' })).toBeVisible()

  await platform.getByRole('button', { name: 'Switch to Platform Engineering' }).click()
  await expect(platform).toContainText('Active workspace')
  await expect(acme.getByRole('button', { name: 'Switch to Acme Engineering' })).toBeVisible()
  await expect.poll(() => page.evaluate(() => localStorage.getItem('dependency-firewall.tenant-id'))).toBe('tenant-platform')
})

test('guides first tenant creation through the shared wizard', async ({ page }) => {
  await installApi(page, { tenants: [] })
  await page.goto('/tenants')

  await expect(page.getByRole('heading', { name: 'No tenants yet' })).toBeVisible()
  await page.getByRole('button', { name: 'New tenant' }).click()
  const dialog = page.getByRole('dialog', { name: 'Create tenant' })
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('Step 1 of 2')
  await expect(page.getByRole('button', { name: 'Review details' })).toBeDisabled()

  await page.getByLabel('Tenant name').fill('Security Engineering')
  await page.getByRole('button', { name: 'Review details' }).click()
  await expect(page.getByRole('heading', { name: 'Review workspace' })).toBeVisible()
  await expect(dialog).toContainText('Security Engineering')
  await page.getByRole('button', { name: 'Create tenant' }).click()
  await expect(page.getByText('Tenant created')).toBeVisible()
  await expect(page.getByRole('listitem').filter({ hasText: 'Security Engineering' })).toContainText('Active workspace')
})

test('recovers tenant discovery without leaving the page', async ({ page }) => {
  await installApi(page, { tenantListFailures: 2 })
  await page.goto('/tenants')

  await expect(page.getByRole('heading', { name: 'Something went wrong' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'New tenant' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Retry' }).click()
  await expect(page.getByRole('list', { name: 'Tenant workspaces' })).toContainText('Acme Engineering')
})
