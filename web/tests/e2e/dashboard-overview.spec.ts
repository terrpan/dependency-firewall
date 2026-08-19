import { expect, installApi, installAuth, policyOverviewFixtures, test } from './fixtures'

test.beforeEach(async ({ page }) => {
  await installAuth(page)
})

test('summarizes protection and leads with the next operational action', async ({ page }) => {
  await installApi(page, { policies: policyOverviewFixtures })
  await page.goto('/')

  await expect(
    page.getByText('See what is protected, what was blocked, and what needs your attention for Acme Engineering.'),
  ).toBeVisible()
  await expect(page.getByText('Decisions reviewed').locator('..')).toContainText('1')
  await expect(page.getByText('Blocked', { exact: true }).locator('..')).toContainText('1')
  await expect(page.getByText('Enforcing policies').locator('..')).toContainText('1')
  await expect(page.getByText('Registry upstreams').locator('..')).toContainText('1')

  const attention = page.getByRole('heading', { name: 'Needs attention' }).locator('xpath=ancestor::section[1]')
  await expect(attention).toContainText('1 to review')
  await expect(attention).toContainText('react@19.2.0 was blocked')
  await expect(attention.getByRole('link', { name: 'Review decision' })).toHaveAttribute('href', '/evaluations')

  const readiness = page.getByRole('heading', { name: 'Protection readiness' }).locator('xpath=ancestor::section[1]')
  await expect(readiness).toContainText('Policy enforcement active')
  await expect(readiness).toContainText('1 policy is enforcing')
  await expect(readiness.getByRole('link', { name: 'Manage policies' })).toHaveAttribute('href', '/policies')

  await expect(page.getByRole('heading', { name: 'Latest decisions' })).toBeVisible()
  await expect(page.getByText('Cache usage')).toHaveCount(0)
  await expect(page.getByText('Recent policy spread')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Health' })).toHaveCount(0)
})

test('turns incomplete setup into a direct next step', async ({ page }) => {
  await installApi(page)
  await page.goto('/')

  const attention = page.getByRole('heading', { name: 'Needs attention' }).locator('xpath=ancestor::section[1]')
  await expect(attention).toContainText('No policies configured')
  await expect(attention.getByRole('link', { name: 'Create policy' })).toHaveAttribute('href', '/policies')

  const readiness = page.getByRole('heading', { name: 'Protection readiness' }).locator('xpath=ancestor::section[1]')
  await expect(readiness).toContainText('Policy enforcement active')
  await expect(readiness).toContainText('Enable a reviewed policy outside dry-run mode')
})

test('treats unavailable evaluation history as an attention item', async ({ page }) => {
  await installApi(page, { evaluationListFailures: 2, policies: policyOverviewFixtures })
  await page.goto('/')

  const attention = page.getByRole('heading', { name: 'Needs attention' }).locator('xpath=ancestor::section[1]')
  await expect(attention).toContainText('1 to review')
  await expect(attention).toContainText('Decision history unavailable')
  await expect(attention).toContainText('the dashboard cannot confirm current protection results')
  await expect(attention).not.toContainText('No action required')
  await expect(attention.getByRole('link', { name: 'Review decisions' })).toHaveAttribute('href', '/evaluations')

  await expect(page.getByText('Unable to load evaluation preview')).toBeVisible()
})
