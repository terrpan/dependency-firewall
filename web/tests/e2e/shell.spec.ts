import { expect, installApi, installAuth, policyOverviewFixtures, test } from './fixtures'

test.beforeEach(async ({ page }) => { await installAuth(page); await installApi(page, { policies: policyOverviewFixtures }) })

test('renders the light operations shell and attaches bearer auth', async ({ page }, testInfo) => {
  let authorization = ''
  page.on('request', request => { if (request.url().includes('/api/v1/')) authorization = request.headers().authorization ?? authorization })
  await page.goto('/')
  await expect(page.getByRole('complementary', { name: 'Primary' })).toBeVisible()
  await expect(page.getByTestId('active-tenant-name')).toHaveText('Acme Engineering')
  await expect.poll(() => authorization).toBe('Bearer playwright-access-token')
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('light-dashboard.png'), fullPage: true })
})

test('mobile drawer is keyboard-accessible', async ({ page }, testInfo) => {
  test.skip(test.info().project.name !== 'mobile-chromium', 'mobile project only')
  await page.goto('/')
  await page.getByRole('button', { name: 'Open navigation' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('complementary', { name: 'Primary' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('mobile-navigation.png'), fullPage: true })
})

test('keeps the navigation rail at compact desktop widths', async ({ page }) => {
  test.skip(test.info().project.name !== 'desktop-chromium', 'desktop project only')

  for (const width of [1024, 768]) {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('/')

    const navigationRail = page.getByRole('complementary', { name: 'Primary' })
    await expect(navigationRail).toBeVisible()
    await expect(page.getByRole('button', { name: 'Open navigation' })).toBeHidden()
    await expect.poll(async () => Math.round((await navigationRail.boundingBox())?.x ?? -1)).toBe(0)
    await expect.poll(async () => Math.round((await navigationRail.boundingBox())?.width ?? -1)).toBe(260)
  }
})

test('persists and renders dark theme', async ({ page }, testInfo) => {
  await page.addInitScript(() => localStorage.setItem('dependency-firewall-theme', 'dark'))
  await page.goto('/')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('dark-shell.png'), fullPage: true })
})

test('allows provider-free local anonymous mode', async ({ page }) => {
  await installAuth(page, 'anonymous')
  await page.goto('/tenants')
  await expect(page.locator('[data-auth-status="anonymous"]')).toBeVisible()
})

test('renders unauthorized state', async ({ page }) => {
  await installAuth(page, 'unauthorized')
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible()
})

test('renders expired-session state', async ({ page }) => {
  await installAuth(page, 'expired')
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Session expired' })).toBeVisible()
})
