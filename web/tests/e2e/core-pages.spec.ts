import { expect, installApi, installAuth, test } from './fixtures'

test.beforeEach(async ({ page }) => { await installAuth(page); await installApi(page) })

test('uses one page-header hierarchy across every route', async ({ page }) => {
  const routes = [
    ['/', 'Dashboard'],
    ['/tenants', 'Tenants'],
    ['/upstreams', 'Upstreams'],
    ['/policies', 'Policies'],
    ['/evaluations', 'Evaluations'],
    ['/dependency-graphs', 'Dependency graphs'],
    ['/missing-route', 'Page not found'],
  ] as const

  let referenceStyle: { fontSize: string; letterSpacing: string; lineHeight: string } | undefined

  for (const [route, title] of routes) {
    await page.goto(route)
    const heading = page.getByRole('heading', { name: title, exact: true })
    await expect(heading).toBeVisible()
    await expect(heading).toHaveJSProperty('tagName', 'H2')

    const style = await heading.evaluate((element) => {
      const computed = getComputedStyle(element)
      return {
        fontSize: computed.fontSize,
        letterSpacing: computed.letterSpacing,
        lineHeight: computed.lineHeight,
      }
    })

    referenceStyle ??= style
    expect(style).toEqual(referenceStyle)
  }

  if (test.info().project.name === 'desktop-chromium') {
    for (const width of [1024, 768]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/policies')
      const heading = page.getByRole('heading', { name: 'Policies', exact: true })
      await expect(heading).toBeVisible()
      await expect.poll(() => heading.evaluate((element) => getComputedStyle(element.closest('header')!).display)).toBe('grid')
    }
  }
})

test('tenant inventory supports selection and creation', async ({ page }) => {
  await page.goto('/tenants')
  await expect(page.getByRole('heading', { name: 'Tenants' })).toBeVisible()
  await expect(page.getByRole('list', { name: 'Tenant workspaces' })).toContainText('Acme Engineering')
  await page.getByRole('button', { name: 'New tenant' }).click()
  await expect(page.getByRole('dialog', { name: 'Create tenant' })).toContainText('Step 1 of 2')
  await page.getByLabel('Tenant name').fill('Platform Engineering')
  await page.getByRole('button', { name: 'Review details' }).click()
  await expect(page.getByRole('heading', { name: 'Review workspace' })).toBeVisible()
  await page.getByRole('button', { name: 'Create tenant' }).click()
  await expect(page.getByText('Tenant created')).toBeVisible()
  await expect(page.getByRole('listitem').filter({ hasText: 'Platform Engineering' })).toContainText('Active workspace')
})

test('unknown routes offer a dashboard recovery action', async ({ page }) => {
  await page.goto('/missing-route')
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Return to dashboard' })).toHaveAttribute('href', '/')
})

test('upstream inventory and creation wizard remain operational', async ({ page }) => {
  await page.goto('/upstreams')
  await expect(page.getByRole('heading', { name: 'Upstreams', exact: true })).toBeVisible()
  await expect(page.getByRole('list', { name: 'Configured upstreams' })).toContainText('npm registry')
  await expect(page.getByRole('link', { name: 'https://registry.npmjs.org' })).toBeVisible()

  await page.getByRole('button', { name: 'New upstream' }).click()
  const createUpstreamDialog = page.getByRole('dialog', { name: 'Create upstream' })
  await expect(createUpstreamDialog).toBeVisible()
  await expect(createUpstreamDialog).toContainText('Step 1 of 2')
  await expect(createUpstreamDialog.getByRole('button', { name: 'Cancel' })).toBeVisible()
  await page.getByLabel('Upstream name').fill('Internal npm')
  await page.getByLabel('Base URL').fill('https://npm.example.test')
  await expect(page.getByText('Enable age-based policies that rely on package publish timestamps.')).toBeVisible()
  await page.getByRole('button', { name: 'Review details' }).click()
  await expect(page.getByRole('heading', { name: 'Review upstream' })).toBeVisible()
  await expect(page.getByRole('dialog', { name: 'Create upstream' })).toContainText('Acme Engineering')
  await page.getByRole('button', { name: 'Create upstream' }).click()
  await expect(page.getByText('Upstream created')).toBeVisible()
})

test('uses consistent colors for equivalent actions', async ({ page }) => {
  await page.goto('/tenants')
  await page.getByRole('button', { name: 'New tenant' }).click()
  await page.getByLabel('Tenant name').fill('Platform Engineering')
  await page.getByRole('button', { name: 'Review details' }).click()
  const createTenant = page.getByRole('button', { name: 'Create tenant' })
  const primaryColors = await createTenant.evaluate(element => {
    const style = getComputedStyle(element)
    return { background: style.backgroundColor, border: style.borderColor, color: style.color }
  })

  await page.goto('/upstreams')
  const newUpstream = page.getByRole('button', { name: 'New upstream' })
  await expect(newUpstream).toBeVisible()
  await expect(newUpstream.evaluate(element => {
    const style = getComputedStyle(element)
    return { background: style.backgroundColor, border: style.borderColor, color: style.color }
  })).resolves.toEqual(primaryColors)

  const refresh = page.getByRole('button', { name: 'Refresh' })
  const neutralColors = await refresh.evaluate(element => {
    const style = getComputedStyle(element)
    return { background: style.backgroundColor, border: style.borderColor, color: style.color }
  })
  await newUpstream.click()
  const cancel = page.getByRole('button', { name: 'Cancel' })
  await expect(cancel.evaluate(element => {
    const style = getComputedStyle(element)
    return { background: style.backgroundColor, border: style.borderColor, color: style.color }
  })).resolves.toEqual(neutralColors)
})
