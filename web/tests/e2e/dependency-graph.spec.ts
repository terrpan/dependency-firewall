import { expect, installApi, installAuth, test } from './fixtures'

test.beforeEach(async ({ page }) => { await installAuth(page); await installApi(page) })

test('filters, selects, highlights, zooms, and deselects graph nodes', async ({ page }, testInfo) => {
  await page.goto('/dependency-graphs')
  const graph = page.getByRole('img', { name: 'Interactive dependency graph' })
  const nodes = page.locator('[data-graph-node="true"]')
  const edges = page.locator('[data-graph-edge="true"]')
  await expect(graph).toBeVisible()
  await expect(nodes).toHaveCount(3)
  await expect(edges).toHaveCount(2)
  await page.screenshot({ path: testInfo.outputPath('graph-default.png'), fullPage: true })

  if (testInfo.project.name === 'desktop-chromium') {
    const navigationRail = page.getByRole('complementary', { name: 'Primary' })
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight))
    await expect.poll(async () => Math.round((await navigationRail.boundingBox())?.y ?? -1)).toBe(0)
    await page.evaluate(() => window.scrollTo(0, 0))
  }

  const draggedNode = nodes.first()
  const connectedLine = edges.first().locator('line').first()
  const originalNodeTransform = await draggedNode.getAttribute('transform')
  const originalLineEndpoints = await connectedLine.evaluate(line =>
    ['x1', 'y1', 'x2', 'y2'].map(attribute => line.getAttribute(attribute)).join(','),
  )
  const nodeBounds = await draggedNode.boundingBox()
  expect(nodeBounds).not.toBeNull()
  await page.mouse.move(nodeBounds!.x + nodeBounds!.width / 2, nodeBounds!.y + nodeBounds!.height / 2)
  await page.mouse.down()
  await page.mouse.move(nodeBounds!.x + nodeBounds!.width / 2 + 80, nodeBounds!.y + nodeBounds!.height / 2 + 48, { steps: 8 })
  await page.mouse.up()
  await expect.poll(() => draggedNode.getAttribute('transform')).not.toBe(originalNodeTransform)
  await expect.poll(() => connectedLine.evaluate(line =>
    ['x1', 'y1', 'x2', 'y2'].map(attribute => line.getAttribute(attribute)).join(','),
  )).not.toBe(originalLineEndpoints)

  await nodes.nth(1).focus()
  await page.keyboard.press('Enter')
  await expect(page.locator('[data-graph-node="true"][data-selected="true"]')).toHaveCount(1)
  await expect(page.locator('[data-graph-edge="true"][data-related="true"]')).toHaveCount(2)
  await expect(page.getByText('Selected package')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('graph-selected.png'), fullPage: true })

  await edges.first().focus()
  await page.keyboard.press('Enter')
  await expect(page.locator('[data-graph-edge="true"][data-selected="true"]')).toHaveCount(1)
  await expect(page.getByText('Selected relationship')).toBeVisible()

  await page.getByRole('button', { name: 'Zoom in' }).click()
  await expect(page.getByText('125%')).toBeVisible()
  await page.getByLabel('Find a package').fill('scheduler')
  await expect(nodes).toHaveCount(1)
  await graph.dispatchEvent('click')
  await expect(page.locator('[data-selected="true"]')).toHaveCount(0)
})
