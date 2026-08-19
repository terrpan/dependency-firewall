// PolicyListPanel renders searchable tenant policies and item-level actions.
import { SearchFilterBar } from '../../components/filters/SearchFilterBar.tsx'
import { policyClass } from './styles.ts'
import type { TypedPolicy, Upstream } from '../../lib/api/index.ts'
import { getPolicyTypeLabel, isPolicyDryRun } from './draft.ts'
import {
  formatPolicyScopeLabel,
  formatPolicyTimestamp,
  formatPolicyActionLabel,
  getPolicyBehaviorSummary,
  getPolicyTargetSummary,
  getActionTone,
} from './display.ts'
import { policyFilterOptions, type PolicyFilter } from './filters.ts'

type PolicyListPanelProps = {
  policies: readonly TypedPolicy[]
  filteredPolicies: readonly TypedPolicy[]
  selectedPolicyId: string | null
  upstreamsCount: number
  upstreamsByID: Map<string, Upstream>
  activeFilters: readonly PolicyFilter[]
  filterCounts: Record<PolicyFilter, number>
  policySearch: string
  hasCreateDraftInProgress: boolean
  canOpenCreateModal: boolean
  canRefresh: boolean
  isUpstreamsFetching: boolean
  isPoliciesFetching: boolean
  isPoliciesError: boolean
  policiesErrorMessage: string | null
  isDeleteError: boolean
  deleteErrorMessage: string
  deletePendingPolicyId: string | null
  togglePendingPolicyId: string | null
  onRefresh: () => void
  onOpenCreate: () => void
  onClearFilters: () => void
  onSearchChange: (value: string) => void
  onToggleFilter: (filter: PolicyFilter) => void
  onOpenDetail: (policyId: string, tab?: 'overview' | 'history') => void
  onEdit: (policy: TypedPolicy) => void
  onDelete: (policy: TypedPolicy) => void
  onTogglePolicy: (policy: TypedPolicy) => void
}

export function PolicyListPanel({
  policies,
  filteredPolicies,
  selectedPolicyId,
  upstreamsCount,
  upstreamsByID,
  activeFilters,
  filterCounts,
  policySearch,
  hasCreateDraftInProgress,
  canOpenCreateModal,
  canRefresh,
  isUpstreamsFetching,
  isPoliciesFetching,
  isPoliciesError,
  policiesErrorMessage,
  isDeleteError,
  deleteErrorMessage,
  deletePendingPolicyId,
  togglePendingPolicyId,
  onRefresh,
  onOpenCreate,
  onClearFilters,
  onSearchChange,
  onToggleFilter,
  onOpenDetail,
  onEdit,
  onDelete,
  onTogglePolicy,
}: PolicyListPanelProps) {
  return (
    <section className={policyClass('card policy-list-card')}>
      <div className={policyClass('policy-section-heading')}>
        <div>
          <h3>Policy overview</h3>
          {policies.length > 0 ? (
            <p className={policyClass('muted')}>Evaluation order is shown first to last; lower priority runs first.</p>
          ) : null}
        </div>
        <div className={policyClass('policy-list-tools')}>
          {activeFilters.length > 0 || policySearch.trim() ? (
            <span className={policyClass('status-pill status-pill-neutral')}>{filteredPolicies.length} shown</span>
          ) : null}
          {isUpstreamsFetching ? (
            <span className={policyClass('status-pill status-pill-neutral')}>Loading upstreams</span>
          ) : null}
          {isPoliciesFetching ? (
            <span className={policyClass('status-pill status-pill-neutral')}>Refreshing</span>
          ) : null}
          <button className={policyClass('secondary-button')} disabled={!canRefresh} onClick={onRefresh} type="button">
            Refresh
          </button>
          {policies.length > 0 ? (
            <button
              className={policyClass('primary-button')}
              disabled={!canOpenCreateModal}
              onClick={onOpenCreate}
              type="button"
            >
              {hasCreateDraftInProgress ? 'Resume draft' : 'New policy'}
            </button>
          ) : null}
        </div>
      </div>

      {isPoliciesError ? (
        <div className={policyClass('policy-error-panel')}>
          <h4>Unable to load policies</h4>
          <p className={policyClass('muted')}>{policiesErrorMessage}</p>
        </div>
      ) : null}

      {isDeleteError ? (
        <div className={policyClass('policy-error-panel')}>
          <h4>Unable to delete policy</h4>
          <p className={policyClass('muted')}>{deleteErrorMessage}</p>
        </div>
      ) : null}

      {policies.length > 0 ? (
        <SearchFilterBar
          activeFilters={activeFilters}
          clearFiltersLabel="Clear filters"
          filterGroupLabel="Policy filters"
          filterOptions={policyFilterOptions.map((filter) => ({
            ...filter,
            count: filterCounts[filter.id],
          }))}
          onClearFilters={onClearFilters}
          onSearchChange={onSearchChange}
          onToggleFilter={onToggleFilter}
          searchHelpText="Search by policy name, type, action, upstream scope, or configuration summary."
          searchInputId="policy-search"
          searchLabel="Policy search"
          searchPlaceholder="licenses, namespaces, npm registry..."
          searchValue={policySearch}
        />
      ) : null}

      {!isPoliciesError && policies.length === 0 ? (
        <div className={policyClass('policy-empty-state')}>
          <h4>No policies yet</h4>
          <p className={policyClass('muted')}>
            {upstreamsCount === 0
              ? 'Add an upstream first so the policy can be scoped to a registry.'
              : 'Create a policy and choose where it applies. It stays disabled until you are ready to enforce it.'}
          </p>
          <div className={policyClass('policy-empty-actions')}>
            <button
              className={policyClass('primary-button')}
              disabled={!canOpenCreateModal}
              onClick={onOpenCreate}
              type="button"
            >
              Create first policy
            </button>
          </div>
        </div>
      ) : null}

      {!isPoliciesError && policies.length > 0 && filteredPolicies.length === 0 ? (
        <div className={policyClass('policy-empty-state')}>
          <h4>No policies match this search and filter state</h4>
          <p className={policyClass('muted')}>
            Try a different search or filter combination to bring matching policies back into view.
          </p>
          <div className={policyClass('policy-empty-actions')}>
            <button className={policyClass('secondary-button')} onClick={onClearFilters} type="button">
              Clear filters
            </button>
          </div>
        </div>
      ) : null}

      <div className={policyClass('policy-list')} role="list">
        {filteredPolicies.map((policy) => {
          const isDeletePending = deletePendingPolicyId === policy.id
          const isTogglePending = togglePendingPolicyId === policy.id
          const isDryRun = isPolicyDryRun(policy)
          const stateLabel = !policy.enabled ? 'Disabled' : isDryRun ? 'Dry run' : 'Enforcing'
          const stateTone = !policy.enabled
            ? 'policy-badge-muted'
            : isDryRun
              ? 'policy-badge-warning'
              : 'policy-badge-success'

          return (
            <article
              key={policy.id}
              className={policyClass('policy-list-item', policy.id === selectedPolicyId && 'selected')}
            >
              <button
                aria-label={`Open details for ${policy.name}`}
                className={policyClass('policy-list-item-main')}
                onClick={() => onOpenDetail(policy.id)}
                type="button"
              >
                <div className={policyClass('policy-list-item-header')}>
                  <div>
                    <h4>{policy.name}</h4>
                    <p className={policyClass('muted')}>{getPolicyTypeLabel(policy.type)}</p>
                  </div>
                  <div className={policyClass('policy-list-item-badges')}>
                    <span className={policyClass('policy-badge', stateTone)}>{stateLabel}</span>
                    <span className={policyClass('policy-badge', getActionTone(policy.action))}>
                      {formatPolicyActionLabel(policy.action)}
                    </span>
                  </div>
                </div>
                <div className={policyClass('policy-behavior-summary')}>
                  <span className={policyClass('policy-config-label')}>What it does</span>
                  <strong>{getPolicyBehaviorSummary(policy)}</strong>
                </div>
                <dl className={policyClass('policy-overview-grid')}>
                  <div>
                    <dt>Applies through</dt>
                    <dd>{formatPolicyScopeLabel(policy, upstreamsByID)}</dd>
                  </div>
                  <div>
                    <dt>Dependencies</dt>
                    <dd>{getPolicyTargetSummary(policy)}</dd>
                  </div>
                  <div>
                    <dt>Evaluation order</dt>
                    <dd>Priority {policy.priority}</dd>
                  </div>
                </dl>
              </button>

              <div className={policyClass('policy-list-item-footer')}>
                <div className={policyClass('policy-list-item-actions')}>
                  <button className={policyClass('policy-card-action')} onClick={() => onEdit(policy)} type="button">
                    Edit
                  </button>
                  <button
                    className={policyClass('policy-card-action')}
                    onClick={() => onOpenDetail(policy.id, 'history')}
                    type="button"
                  >
                    History
                  </button>
                  {!policy.enabled ? (
                    <button
                      className={policyClass('policy-card-action policy-card-action-danger')}
                      disabled={Boolean(deletePendingPolicyId)}
                      onClick={() => onDelete(policy)}
                      type="button"
                    >
                      {isDeletePending ? 'Deleting...' : 'Delete'}
                    </button>
                  ) : null}
                </div>
                <div className={policyClass('policy-list-state-actions')}>
                  <span className={policyClass('policy-updated-copy')}>
                    Updated {formatPolicyTimestamp(policy.updated_at)}
                  </span>
                  <button
                    aria-label={`${policy.enabled ? 'Disable' : 'Enable'} ${policy.name}`}
                    className={policyClass('policy-card-action policy-state-action')}
                    disabled={isTogglePending}
                    onClick={() => onTogglePolicy(policy)}
                    type="button"
                  >
                    {isTogglePending ? 'Saving...' : policy.enabled ? 'Disable' : 'Enable'}
                  </button>
                </div>
              </div>
            </article>
          )
        })}
      </div>
    </section>
  )
}
