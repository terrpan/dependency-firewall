import { expect, installApi, installAuth, policyOverviewFixtures, test } from './fixtures'

test.beforeEach(async ({ page }) => {
  await installAuth(page)
  await installApi(page, { policies: policyOverviewFixtures })
})

test('summarizes policy behavior, scope, state, and evaluation order', async ({ page }, testInfo) => {
  await page.goto('/policies')

  await expect(page.getByText('1 enforcing')).toBeVisible()
  await expect(page.getByText('1 dry run')).toBeVisible()
  await expect(page.getByText('1 disabled')).toBeVisible()
  await expect(page.getByText('Deny packages from blocked namespaces: untrusted, legacy-vendor.')).toBeVisible()
  await expect(
    page.getByText('Would deny packages unless every declared license is approved: MIT, Apache-2.0 +1 more.'),
  ).toBeVisible()
  await expect(
    page.getByText('Would deny packages published less than 7 days ago, except @acme/release-tools.'),
  ).toBeVisible()
  await expect(page.getByText('Direct + Transitive • Production • Unknown graph: Warn only')).toBeVisible()

  const policyNames = await page.locator('article h4').allTextContents()
  expect(policyNames).toEqual(['Block untrusted namespaces', 'Approved licenses', 'Package cooling-off period'])
  await expect(page.getByText('Schema', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Delete' })).toHaveCount(1)
  await expect(page.getByRole('button', { name: 'Disable Block untrusted namespaces' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Enable Package cooling-off period' })).toBeVisible()

  await page.screenshot({ path: testInfo.outputPath('policy-overview.png'), fullPage: true })
})

test('keeps technical metadata behind progressive disclosure', async ({ page }) => {
  await page.goto('/policies')
  await page.getByRole('button', { name: 'Open details for Block untrusted namespaces' }).click()
  const dialog = page.getByRole('dialog', { name: 'Block untrusted namespaces' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('Deny packages from blocked namespaces: untrusted, legacy-vendor.')).toBeVisible()
  await expect(dialog.getByText('policy-blocklist')).toBeHidden()
  await dialog.getByText('Technical details').click()
  await expect(dialog.getByText('policy-blocklist')).toBeVisible()
})
