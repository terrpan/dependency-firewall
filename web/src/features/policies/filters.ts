// Policy filter helpers keep list filter definitions and matching rules together.
import type { TypedPolicy } from '../../lib/api/index.ts'
import { isPolicyDryRun } from './draft.ts'

export type PolicyFilter = 'enabled' | 'disabled' | 'dry_run' | 'allow' | 'deny'

export const policyFilterOptions = [
  { id: 'deny', label: 'Deny', tone: 'danger' },
  { id: 'allow', label: 'Allow', tone: 'success' },
  { id: 'enabled', label: 'Enabled', tone: 'info' },
  { id: 'disabled', label: 'Disabled', tone: 'muted' },
  { id: 'dry_run', label: 'Dry run', tone: 'warning' },
] as const

export function matchesPolicyFilter(policy: TypedPolicy, filter: PolicyFilter) {
  if (filter === 'enabled') {
    return policy.enabled
  }

  if (filter === 'disabled') {
    return !policy.enabled
  }

  if (filter === 'allow') {
    return policy.action === 'allow'
  }

  if (filter === 'deny') {
    return policy.action === 'deny'
  }

  return isPolicyDryRun(policy)
}
