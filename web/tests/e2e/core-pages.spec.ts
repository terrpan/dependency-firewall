import { expect, installApi, installAuth, test } from './fixtures'

test.beforeEach(async ({ page }) => { await installAuth(page); await installApi(page) })

test('tenant inventory supports selection and creation', async ({ page }) => {
  await page.goto('/tenants')
  await expect(page.getByRole('heading', { name: 'Tenants' })).toBeVisible()
  await expect(page.getByRole('list', { name: 'Tenants' })).toContainText('Acme Engineering')
  await page.getByLabel('Display name').fill('Platform Engineering')
  await page.getByRole('button', { name: 'Create tenant' }).click()
  await expect(page.getByText('Tenant created')).toBeVisible()
})

test('unknown routes offer a dashboard recovery action', async ({ page }) => {
  await page.goto('/missing-route')
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Return to dashboard' })).toHaveAttribute('href', '/')
})
