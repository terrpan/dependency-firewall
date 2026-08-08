// PolicyListPanel renders searchable tenant policies and item-level actions.
import { SearchFilterBar } from '../../components/filters/SearchFilterBar.tsx'
import { policyClass } from './styles.ts'
import type { TypedPolicy, Upstream } from '../../lib/api/index.ts'
import { getPolicyTypeLabel, isPolicyDryRun } from './draft.ts'
import {
  formatPolicyScopeCaption,
  formatPolicyScopeLabel,
  formatPolicyTimestamp,
  getActionTone,
  getEnabledTone,
  getPolicyConfigDetail,
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
    <section className={policyClass("card policy-list-card")}>
      <div className={policyClass("policy-section-heading")}>
        <div>
          <h3>Current tenant policies</h3>
        </div>
        <div className={policyClass("policy-list-tools")}>
          {activeFilters.length > 0 || policySearch.trim() ? (
            <span className={policyClass("status-pill status-pill-neutral")}>{filteredPolicies.length} shown</span>
          ) : null}
          {isUpstreamsFetching ? <span className={policyClass("status-pill status-pill-neutral")}>Loading upstreams</span> : null}
          {isPoliciesFetching ? <span className={policyClass("status-pill status-pill-neutral")}>Refreshing</span> : null}
          <button
            className={policyClass("secondary-button")}
            disabled={!canRefresh}
            onClick={onRefresh}
            type="button"
          >
            Refresh
          </button>
          {policies.length > 0 ? (
            <button className={policyClass("primary-button")} disabled={!canOpenCreateModal} onClick={onOpenCreate} type="button">
              {hasCreateDraftInProgress ? 'Resume draft' : 'New policy'}
            </button>
          ) : null}
        </div>
      </div>

      {isPoliciesError ? (
        <div className={policyClass("policy-error-panel")}>
          <h4>Unable to load policies</h4>
          <p className={policyClass("muted")}>{policiesErrorMessage}</p>
        </div>
      ) : null}

      {isDeleteError ? (
        <div className={policyClass("policy-error-panel")}>
          <h4>Unable to delete policy</h4>
          <p className={policyClass("muted")}>{deleteErrorMessage}</p>
        </div>
      ) : null}

      {policies.length > 0 ? <SearchFilterBar
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
        searchPlaceholder="block_cvss, cvss_threshold, npm upstream..."
        searchValue={policySearch}
      /> : null}

      {!isPoliciesError && policies.length === 0 ? (
        <div className={policyClass("policy-empty-state")}>
          <h4>No policies yet</h4>
          <p className={policyClass("muted")}>
            {upstreamsCount === 0
              ? 'Add an upstream first so the policy can be scoped to a registry.'
              : 'Create a policy and choose where it applies. It stays disabled until you are ready to enforce it.'}
          </p>
          <div className={policyClass("policy-empty-actions")}>
            <button className={policyClass("primary-button")} disabled={!canOpenCreateModal} onClick={onOpenCreate} type="button">
              Create first policy
            </button>
          </div>
        </div>
      ) : null}

      {!isPoliciesError && policies.length > 0 && filteredPolicies.length === 0 ? (
        <div className={policyClass("policy-empty-state")}>
          <h4>No policies match this search and filter state</h4>
          <p className={policyClass("muted")}>Try a different search or filter combination to bring matching policies back into view.</p>
          <div className={policyClass("policy-empty-actions")}>
            <button className={policyClass("secondary-button")} onClick={onClearFilters} type="button">
              Clear filters
            </button>
          </div>
        </div>
      ) : null}

      <div className={policyClass("policy-list")} role="list">
        {filteredPolicies.map((policy) => {
          const configDetail = getPolicyConfigDetail(policy)
          const isDeletePending = deletePendingPolicyId === policy.id
          const isTogglePending = togglePendingPolicyId === policy.id

          return (
            <article
              key={policy.id}
              className={policyClass('policy-list-item', policy.id === selectedPolicyId && 'selected')}
            >
              <button
                className={policyClass("policy-list-item-main")}
                onClick={() => onOpenDetail(policy.id)}
                type="button"
              >
                <div className={policyClass("policy-list-item-header")}>
                  <div>
                    <h4>{policy.name}</h4>
                    <p className={policyClass("muted")}>{getPolicyTypeLabel(policy.type)}</p>
                    <p className={policyClass("policy-scope-copy")}>{formatPolicyScopeCaption(policy, upstreamsByID)}</p>
                  </div>
                  <div className={policyClass("policy-list-item-badges")}>
                    <span className={policyClass('policy-badge', getActionTone(policy.action))}>{policy.action}</span>
                    <span className={policyClass('policy-badge', getEnabledTone(policy.enabled))}>
                      {policy.enabled ? 'enabled' : 'disabled'}
                    </span>
                    {isPolicyDryRun(policy) ? <span className={policyClass("policy-badge policy-badge-muted")}>dry run</span> : null}
                  </div>
                </div>
                <div className={policyClass("policy-config-summary")}>
                  <span className={policyClass("policy-config-label")}>{configDetail.label}</span>
                  <span className={policyClass("policy-config-value")}>{configDetail.value}</span>
                </div>
                <dl className={policyClass("metadata-list compact-metadata-list compact-metadata-list-dense")}>
                  <div>
                    <dt>Scope</dt>
                    <dd>{formatPolicyScopeLabel(policy, upstreamsByID)}</dd>
                  </div>
                  <div>
                    <dt>Priority</dt>
                    <dd>{policy.priority}</dd>
                  </div>
                  <div>
                    <dt>Schema</dt>
                    <dd>v{policy.schema_version}</dd>
                  </div>
                  <div>
                    <dt>Version</dt>
                    <dd>{policy.version}</dd>
                  </div>
                  <div>
                    <dt>Created</dt>
                    <dd>{formatPolicyTimestamp(policy.created_at)}</dd>
                  </div>
                  <div>
                    <dt>Updated</dt>
                    <dd>{formatPolicyTimestamp(policy.updated_at)}</dd>
                  </div>
                </dl>
              </button>

              <div className={policyClass("policy-list-item-footer")}>
                <div className={policyClass("policy-list-item-actions")}>
                  <button className={policyClass("policy-card-action")} onClick={() => onEdit(policy)} type="button">
                    Edit
                  </button>
                  <button className={policyClass("policy-card-action")} onClick={() => onOpenDetail(policy.id, 'history')} type="button">
                    History
                  </button>
                  <button
                    className={policyClass("policy-card-action policy-card-action-danger")}
                    disabled={policy.enabled || Boolean(deletePendingPolicyId)}
                    onClick={() => onDelete(policy)}
                    title={policy.enabled ? 'Disable the policy before deleting it.' : undefined}
                    type="button"
                  >
                    {policy.enabled ? 'Disable first' : isDeletePending ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
                <div className={policyClass("policy-inline-toggle")}>
                  <span className={policyClass("policy-inline-toggle-label")}>Enabled</span>
                  <button
                    className={policyClass('policy-enabled-toggle', policy.enabled && 'active')}
                    disabled={isTogglePending}
                    onClick={() => onTogglePolicy(policy)}
                    type="button"
                  >
                    {isTogglePending ? 'Saving...' : policy.enabled ? 'true' : 'false'}
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
