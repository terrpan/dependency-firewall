import { expect, test } from '@playwright/test'
import { buildPolicyDraftInput, createPolicyDraftForType, createPolicyDraftFromPolicy } from '../../src/features/policies/draft'

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
