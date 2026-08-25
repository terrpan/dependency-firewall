import { expect, installApi, installAuth, tenantOverviewFixtures, test } from './fixtures'

test.beforeEach(async ({ page }) => {
  await installAuth(page)
})

test('makes the active workspace and tenant switching explicit', async ({ page }) => {
  await installApi(page, { tenants: tenantOverviewFixtures })
  await page.goto('/tenants')

  await expect(
    page.getByText(
      'Choose which tenant to operate in. Upstreams, policies, decisions, and dependency graphs stay inside that workspace.',
    ),
  ).toBeVisible()
  const list = page.getByRole('list', { name: 'Tenant workspaces' })
  const acme = list.getByRole('listitem').filter({ hasText: 'Acme Engineering' })
  const platform = list.getByRole('listitem').filter({ hasText: 'Platform Engineering' })

  await expect(acme).toContainText('Active workspace')
  await expect(acme.getByRole('link', { name: 'Open dashboard' })).toHaveAttribute('href', '/')
  await expect(platform.getByRole('button', { name: 'Switch to Platform Engineering' })).toBeVisible()

  await platform.getByRole('button', { name: 'Switch to Platform Engineering' }).click()
  await expect(platform).toContainText('Active workspace')
  await expect(acme.getByRole('button', { name: 'Switch to Acme Engineering' })).toBeVisible()
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem('dependency-firewall.tenant-id')))
    .toBe('tenant-platform')
})

test('guides first tenant creation through the shared wizard', async ({ page }) => {
  await installApi(page, { enrollmentPublicAPIURL: 'https://host.docker.internal:8443', tenants: [] })
  await page.goto('/tenants')

  await expect(page.getByRole('heading', { name: 'No tenants yet' })).toBeVisible()
  await page.getByRole('button', { name: 'New tenant' }).click()
  const dialog = page.getByRole('dialog', { name: 'Create tenant' })
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('Step 1 of 3')
  await expect(page.getByRole('button', { name: 'Continue' })).toBeDisabled()

  await page.getByLabel('Tenant name').fill('Security Engineering')
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.getByRole('heading', { name: 'Choose proxy runtime' })).toBeVisible()
  await expect(page.getByLabel('Self-hosted proxy')).toBeChecked()
  await expect(page.getByLabel('Hosted proxy unavailable')).toBeDisabled()
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.getByRole('heading', { name: 'Review workspace' })).toBeVisible()
  await expect(dialog).toContainText('Security Engineering')
  await page.getByRole('button', { name: 'Create tenant' }).click()
  await expect(page.getByRole('dialog', { name: 'Tenant created' })).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Docker', exact: true })).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Docker Compose' })).toBeVisible()
  await expect(page.getByText('FIREWALL_ENROLLMENT_PUBLIC_API_URL: https://host.docker.internal:8443')).toBeVisible()
  await expect(page.getByText('host.docker.internal:host-gateway')).toBeVisible()
  const publishPort = page.getByLabel('Publish proxy port')
  await expect(publishPort).not.toBeChecked()
  await expect(page.getByText('FIREWALL_SERVER_PORT')).toHaveCount(0)
  await publishPort.check()
  const proxyPort = page.getByLabel('Proxy port', { exact: true })
  await proxyPort.fill('0')
  await expect(proxyPort).toHaveAttribute('aria-invalid', 'true')
  await expect(page.getByRole('button', { name: 'Copy Docker Compose commands' })).toBeDisabled()
  await proxyPort.fill('8181')
  await expect(page.getByText('FIREWALL_SERVER_PORT: "8181"')).toBeVisible()
  await expect(page.getByText('- "8181:8181"')).toBeVisible()
  await page.getByRole('button', { name: 'Copy Docker Compose commands' }).click()
  await expect(page.getByRole('button', { name: 'Docker Compose commands copied' })).toBeVisible()

  await page.getByLabel('Use an additional CA bundle').check()
  await expect(page.getByText('FIREWALL_ENROLLMENT_ADDITIONAL_CA_FILE: /etc/firewall/additional-ca.pem')).toBeVisible()
  await page.getByRole('tab', { name: 'Docker run' }).click()
  await expect(page.getByText('docker start dependency-firewall-valkey')).toBeVisible()
  await expect(page.getByText('--add-host host.docker.internal:host-gateway')).toBeVisible()
  await expect(page.getByText('-p 8181:8181')).toBeVisible()
  await expect(page.getByText('-e FIREWALL_SERVER_PORT=8181')).toBeVisible()
  await expect(
    page.getByText('-e FIREWALL_ENROLLMENT_ADDITIONAL_CA_FILE=/etc/firewall/additional-ca.pem'),
  ).toBeVisible()
  await expect(page.getByText('docker run --rm --name dependency-firewall-proxy')).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Helm — unavailable' })).toBeDisabled()
  await expect(page.getByRole('listitem').filter({ hasText: 'Security Engineering' })).toContainText('Active workspace')
})

test('activates a proxy and waits for its first connection', async ({ page }) => {
  await installApi(page)
  await page.goto('/activate')
  await page.getByLabel('Activation code').fill('ABCD-EFGH')
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.getByRole('heading', { name: 'Confirm proxy' })).toBeVisible()
  await expect(page.getByLabel('Installation name')).toHaveValue('Edge proxy')
  await page.getByRole('button', { name: 'Approve proxy' }).click()
  await expect(page.getByRole('heading', { name: 'Proxy connected' })).toBeVisible()
})

test('shows an expired or already-used activation code', async ({ page }) => {
  await installApi(page, { activationResolveStatus: 410 })
  await page.goto('/activate')
  await page.getByLabel('Activation code').fill('ABCD-EFGH')
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.getByText('This code expired or was already used.')).toBeVisible()
})

test('recovers tenant discovery without leaving the page', async ({ page }) => {
  await installApi(page, { tenantListFailures: 2 })
  await page.goto('/tenants')

  await expect(page.getByRole('heading', { name: 'Something went wrong' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'New tenant' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Retry' }).click()
  await expect(page.getByRole('list', { name: 'Tenant workspaces' })).toContainText('Acme Engineering')
})
