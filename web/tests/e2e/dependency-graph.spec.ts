import { expect, installApi, installAuth, test } from './fixtures'

test.beforeEach(async ({ page }) => { await installAuth(page); await installApi(page) })

test('filters, selects, highlights, zooms, and deselects graph nodes', async ({ page }, testInfo) => {
  await page.goto('/dependency-graphs')
  const graph = page.getByRole('img', { name: 'Interactive dependency graph' })
  await expect(graph).toBeVisible()
  await expect(page.locator('.graph-node')).toHaveCount(3)
  await page.screenshot({ path: testInfo.outputPath('graph-default.png'), fullPage: true })

  await page.locator('.graph-node').nth(1).focus()
  await page.keyboard.press('Enter')
  await expect(page.locator('.graph-node-selected')).toHaveCount(1)
  await expect(page.getByText('Selected package')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('graph-selected.png'), fullPage: true })

  await page.getByRole('button', { name: 'Zoom in' }).click()
  await expect(page.getByText('125%')).toBeVisible()
  await page.getByLabel('Find a package').fill('scheduler')
  await expect(page.locator('.graph-node')).toHaveCount(1)
  await graph.dispatchEvent('click')
  await expect(page.locator('.graph-node-selected')).toHaveCount(0)
})
