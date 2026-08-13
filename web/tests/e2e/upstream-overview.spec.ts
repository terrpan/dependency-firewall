import {
  expect,
  installApi,
  installAuth,
  test,
  upstreamOverviewFixtures,
} from './fixtures'

test.beforeEach(async ({ page }) => {
  await installAuth(page)
})

test('upstream inventory leads from readiness to safe client setup', async ({ page }) => {
  await installApi(page, { upstreams: upstreamOverviewFixtures })
  await page.goto('/upstreams')

  await expect(page.getByText('2 sources')).toBeVisible()
  const inventory = page.getByRole('list', { name: 'Configured upstreams' })
  await expect(inventory).toContainText('registry.npmjs.org')
  await expect(inventory).toContainText('No credentials')
  await expect(inventory).toContainText('3 policy types available')

  await page.getByRole('button', { name: /Private containers/ }).click()
  await expect(page.getByRole('heading', { name: 'Use with Docker' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Private containers' })).toBeVisible()
  await expect(page.getByRole('definition').filter({ hasText: 'Credentials configured for robot' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Copy docker pull' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Copy Optional mirror config' })).toBeVisible()
  await expect(page.getByLabel('Optional mirror config command')).not.toContainText('insecure-registries')

  await expect(page.getByText('oci-private', { exact: true })).not.toBeVisible()
  await page.getByText('Technical details').click()
  await expect(page.getByText('oci-private', { exact: true })).toBeVisible()

  const requestRemoval = page.getByRole('button', { name: 'Remove upstream', exact: true })
  const destructiveColors = await requestRemoval.evaluate(element => {
    const style = getComputedStyle(element)
    return { background: style.backgroundColor, border: style.borderColor, color: style.color }
  })
  await requestRemoval.click()
  const confirmation = page.getByRole('alert').filter({ hasText: 'Remove Private containers?' })
  await expect(confirmation).toBeVisible()
  await expect(confirmation.getByRole('button', { name: 'Remove upstream', exact: true }).evaluate(element => {
    const style = getComputedStyle(element)
    return { background: style.backgroundColor, border: style.borderColor, color: style.color }
  })).resolves.toEqual(destructiveColors)
  await confirmation.getByRole('button', { name: 'Cancel' }).click()
  await expect(confirmation).not.toBeVisible()
})

test('upstream removal stays inline and updates the inventory', async ({ page }) => {
  await installApi(page, { upstreams: upstreamOverviewFixtures })
  await page.goto('/upstreams?upstream=oci-private')

  await page.getByRole('button', { name: 'Remove upstream', exact: true }).click()
  const confirmation = page.getByRole('alert').filter({ hasText: 'Remove Private containers?' })
  await confirmation.getByRole('button', { name: 'Remove upstream', exact: true }).click()

  await expect(page.getByText('Upstream deleted')).toBeVisible()
  await expect(page.getByRole('list', { name: 'Configured upstreams' })).not.toContainText('Private containers')
  await expect(page.getByText('1 source')).toBeVisible()
})

test('empty and failed upstream inventories offer one clear recovery action', async ({ page }) => {
  await installApi(page, { upstreamListFailures: 2, upstreams: [] })
  await page.goto('/upstreams')

  await expect(page.getByRole('alert')).toContainText('Unable to load upstreams')
  await page.getByRole('button', { name: 'Retry' }).click()
  await expect(page.getByRole('heading', { name: 'Connect the first package source' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create upstream' })).toHaveCount(1)
  await expect(page.getByRole('button', { name: 'New upstream' })).toHaveCount(0)
})
