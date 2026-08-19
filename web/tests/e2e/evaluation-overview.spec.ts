import { evaluationOverviewFixtures, expect, installApi, installAuth, test } from './fixtures'

test.beforeEach(async ({ page }) => {
  await installAuth(page)
})

test('evaluation history explains decisions before exposing technical evidence', async ({ page }) => {
  await installApi(page, { evaluations: evaluationOverviewFixtures })
  await page.goto('/evaluations')

  await expect(page.getByText('See what Dependency Firewall decided for Acme Engineering')).toBeVisible()
  const overview = page.getByRole('region', { name: 'Decision overview' })
  await expect(overview).toContainText('Loaded decisions4')
  await expect(overview).toContainText('Allowed2')
  await expect(overview).toContainText('Denied2')
  await expect(overview).toContainText('Dry-run warnings1')

  const reactDecision = page.getByRole('listitem').filter({ hasText: 'react@19.2.0' })
  await expect(reactDecision).toContainText('Namespace matched the tenant blocklist.')
  await expect(reactDecision).toContainText('PolicyProtected namespaces')
  await expect(reactDecision.getByText('evaluation-react', { exact: true })).not.toBeVisible()

  await reactDecision.getByText('Decision details').click()
  await expect(reactDecision.getByText('evaluation-react', { exact: true })).toBeVisible()
  await expect(reactDecision).toContainText('Other matched policies')
  await expect(reactDecision).toContainText('Approved licenses')

  const dryRunDecision = page.getByRole('listitem').filter({ hasText: 'left-pad@1.3.0' })
  await expect(dryRunDecision).toContainText('DRY RUN')
  await dryRunDecision.getByText('Decision details').click()
  await expect(dryRunDecision).toContainText('Dry-run warnings')
  await expect(dryRunDecision).toContainText('would deny because license metadata is unavailable')
})

test('evaluation filters narrow results and keep outcomes mutually exclusive', async ({ page }) => {
  await installApi(page, { evaluations: evaluationOverviewFixtures })
  await page.goto('/evaluations')

  const allow = page.getByRole('button', { name: /Allow 2/ })
  const deny = page.getByRole('button', { name: /Deny 2/ })
  const cached = page.getByRole('button', { name: /Cached 2/ })

  await allow.click()
  await cached.click()
  await expect(page.getByRole('list', { name: 'Evaluation decisions' }).getByRole('listitem')).toHaveCount(1)
  await expect(page.getByRole('list', { name: 'Evaluation decisions' })).toContainText('lodash@4.17.21')

  await deny.click()
  await expect(allow).toHaveAttribute('aria-pressed', 'false')
  await expect(deny).toHaveAttribute('aria-pressed', 'true')
  await expect(cached).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByRole('list', { name: 'Evaluation decisions' })).toContainText('library/nginx@sha256')
  await expect(page.getByText('1 of 4 loaded decisions match.')).toBeVisible()
})

test('artifact search and clear filters provide direct recovery', async ({ page }) => {
  await installApi(page, { evaluations: evaluationOverviewFixtures })
  await page.goto('/evaluations')

  await page.getByLabel('Artifact search').fill('missing-package')
  await expect(page.getByText('No matching decisions', { exact: true })).toBeVisible()

  await page.getByLabel('Artifact search').fill('nginx')
  await expect(page.getByRole('list', { name: 'Evaluation decisions' })).toContainText('library/nginx@sha256')
})

test('empty and failed decision history explain the next step', async ({ page }) => {
  await installApi(page, { evaluationListFailures: 2, evaluations: [] })
  await page.goto('/evaluations')

  await expect(page.getByText('Unable to load decision history')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Refresh' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Retry' }).click()
  await expect(page.getByText('No decisions recorded yet', { exact: true })).toBeVisible()
  await expect(
    page.getByText(
      'Decisions appear here after this tenant routes package or image requests through Dependency Firewall.',
    ),
  ).toBeVisible()
})
