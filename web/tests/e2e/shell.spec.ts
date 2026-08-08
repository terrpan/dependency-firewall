import { expect, installApi, installAuth, test } from './fixtures'

test.beforeEach(async ({ page }) => { await installAuth(page); await installApi(page) })

test('renders the light operations shell and attaches bearer auth', async ({ page }, testInfo) => {
  let authorization = ''
  page.on('request', request => { if (request.url().includes('/api/v1/')) authorization = request.headers().authorization ?? authorization })
  await page.goto('/')
  await expect(page.getByRole('complementary', { name: 'Primary' })).toBeVisible()
  await expect(page.locator('.tenant-active strong')).toHaveText('Acme Engineering')
  await expect.poll(() => authorization).toBe('Bearer playwright-access-token')
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

test('persists and renders dark theme', async ({ page }, testInfo) => {
  await page.addInitScript(() => localStorage.setItem('dependency-firewall-theme', 'dark'))
  await page.goto('/')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.screenshot({ path: testInfo.outputPath('dark-shell.png'), fullPage: true })
})

test('allows provider-free local anonymous mode', async ({ page }) => {
  await installAuth(page, 'anonymous')
  await page.goto('/tenants')
  await expect(page.getByText('Authentication not configured')).toBeVisible()
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
