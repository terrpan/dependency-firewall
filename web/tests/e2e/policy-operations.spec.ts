import { expect, test } from '@playwright/test'
import {
  buildPolicyDraftInput,
  createPolicyDraftForType,
  createPolicyDraftFromPolicy,
} from '../../src/features/policies/draft'
import { installApi, installAuth } from './fixtures'

test('unknown dependency scope round-trips through policy editing', () => {
  const draft = {
    ...createPolicyDraftForType('blocklist'),
    upstreamId: 'upstream-npm',
    name: 'Unknown dependency guard',
    targetEnabled: true,
    targetDependencyScopes: ['unknown'] as const,
    targetOnUnknown: 'deny' as const,
  }
  const input = buildPolicyDraftInput(draft)
  expect(input.target).toEqual({ dependency_scope: ['unknown'], on_unknown: 'deny' })

  const editDraft = createPolicyDraftFromPolicy({
    ...input,
    id: 'policy-unknown',
    tenant_id: 'tenant-acme',
    version: 1,
    created_at: '2026-08-08T10:00:00Z',
    updated_at: '2026-08-08T10:00:00Z',
  })
  expect(editDraft.targetDependencyScopes).toEqual(['unknown'])
  expect(editDraft.targetOnUnknown).toBe('deny')
})

test('policy wizard and evaluation filters are keyboard-operable', async ({ page }) => {
  await installAuth(page)
  await installApi(page)
  await page.goto('/policies')
  await page.getByRole('button', { name: 'Create first policy' }).click()
  const policyDialog = page.getByRole('dialog', { name: 'Create policy' })
  await expect(policyDialog).toBeVisible()
  await expect(policyDialog).toContainText('Step 1 of 6')
  await expect(policyDialog.getByRole('button', { name: 'Cancel' })).toBeVisible()
  await expect(policyDialog.getByRole('button', { name: 'Start over' })).toBeVisible()
  await page.getByRole('button', { name: /npm registry/i }).click()
  await expect(page.getByRole('heading', { name: 'Choose type' })).toBeVisible()
  await page.getByRole('button', { name: /Namespace blocklist blocklist/i }).click()
  await expect(page.getByRole('heading', { name: 'Set basics' })).toBeVisible()
  await page.keyboard.press('Escape')

  await page.goto('/evaluations')
  const search = page.getByLabel('Artifact search')
  await search.fill('missing@1')
  await expect(search).toHaveValue('missing@1')
  const denyFilter = page.getByRole('button', { name: /Deny/ })
  await denyFilter.focus()
  await page.keyboard.press('Enter')
  await expect(denyFilter).toHaveAttribute('aria-pressed', 'true')
})
