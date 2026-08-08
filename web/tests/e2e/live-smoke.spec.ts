import { expect, test } from '@playwright/test'

test('live control plane shell is reachable', async ({ page }) => {
  test.skip(!process.env.PLAYWRIGHT_LIVE_BASE_URL, 'requires PLAYWRIGHT_LIVE_BASE_URL and a prepared tenant')
  await page.goto('/')
  await expect(page.getByRole('navigation', { name: 'Primary' })).toBeVisible()
})
