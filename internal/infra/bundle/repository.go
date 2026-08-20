package bundle

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// PolicyRepository adapts tenant bundles to the core policy repository port for the proxy runtime.
type PolicyRepository struct {
	provider port.TenantBundleProvider
}

// NewPolicyRepository creates a new bundle-backed policy repository.
func NewPolicyRepository(provider port.TenantBundleProvider) *PolicyRepository {
	return &PolicyRepository{provider: provider}
}

// GetByID returns one policy from the tenant bundle.
func (r *PolicyRepository) GetByID(ctx context.Context, tenantID, id string) (*domain.Policy, error) {
	bundle, err := r.provider.GetTenantBundle(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	for i := range bundle.Policies {
		policyDef := bundle.Policies[i]
		policyDef.NormalizeScope()
		if policyDef.ID == id && policyDef.ScopeKind == domain.PolicyScopeAccount {
			return &policyDef, nil
		}
	}

	return nil, domain.ErrPolicyNotFound
}

// ListByTenant returns policies from the tenant bundle.
func (r *PolicyRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Policy, error) {
	bundle, err := r.provider.GetTenantBundle(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	policies := make([]domain.Policy, 0, len(bundle.Policies))
	for i := range bundle.Policies {
		policyDef := bundle.Policies[i]
		policyDef.NormalizeScope()
		if policyDef.ScopeKind == domain.PolicyScopeAccount {
			policies = append(policies, policyDef)
		}
	}
	return policies, nil
}

// GetEffectiveByID performs the get effective by id operation.
func (r *PolicyRepository) GetEffectiveByID(
	ctx context.Context,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Policy, error) {
	policies, err := r.ListEffective(ctx, scope)
	if err != nil {
		return nil, err
	}
	for i := range policies {
		if policies[i].ID == id {
			return &policies[i], nil
		}
	}
	return nil, domain.ErrPolicyNotFound
}

// ListAccount performs the list account operation.
func (r *PolicyRepository) ListAccount(ctx context.Context, tenantID string) ([]domain.Policy, error) {
	return r.ListByTenant(ctx, tenantID)
}

// ListByOrganization performs the list by organization operation.
func (r *PolicyRepository) ListByOrganization(
	ctx context.Context,
	tenantID string,
	organizationID string,
) ([]domain.Policy, error) {
	return r.listPolicies(ctx, domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID}, false)
}

// ListEffective performs the list effective operation.
func (r *PolicyRepository) ListEffective(
	ctx context.Context,
	scope domain.AuthorizationScope,
) ([]domain.Policy, error) {
	return r.listPolicies(ctx, scope, true)
}

func (r *PolicyRepository) listPolicies(
	ctx context.Context,
	scope domain.AuthorizationScope,
	includeAccount bool,
) ([]domain.Policy, error) {
	bundle, err := r.provider.GetTenantBundle(ctx, scope.TenantID)
	if err != nil {
		return nil, err
	}
	policies := make([]domain.Policy, 0, len(bundle.Policies))
	for i := range bundle.Policies {
		policyDef := bundle.Policies[i]
		policyDef.NormalizeScope()
		isAccount := includeAccount && policyDef.ScopeKind == domain.PolicyScopeAccount
		isOrganization := policyDef.ScopeKind == domain.PolicyScopeOrganization &&
			policyDef.OrganizationID == scope.OrganizationID
		if isAccount || isOrganization {
			policies = append(policies, policyDef)
		}
	}
	return policies, nil
}

// ListVersions always fails: a tenant bundle is a flattened snapshot of the current policy set and carries no version
// history. Policy version history is only available through the control plane's database-backed repository.
func (r *PolicyRepository) ListVersions(context.Context, string, string, int) ([]domain.PolicyVersion, error) {
	return nil, fmt.Errorf("bundle policy repository is read-only")
}

// RollbackToVersion always fails. The proxy runtime consumes bundles read-only; rolling a policy back is a
// control-plane mutation that must go through the owning service so a new version and revision are recorded.
func (r *PolicyRepository) RollbackToVersion(context.Context, string, string, int) (*domain.Policy, error) {
	return nil, fmt.Errorf("bundle policy repository is read-only")
}

// Create always fails. It exists only to satisfy the policy repository port; the proxy runtime never authors policies,
// which are created in the control plane and reach the proxy through a refreshed bundle.
func (r *PolicyRepository) Create(context.Context, *domain.Policy) error {
	return fmt.Errorf("bundle policy repository is read-only")
}

// Update always fails, for the same reason as Create: bundle-backed policies are a distributed snapshot and cannot be
// mutated from the proxy side.
func (r *PolicyRepository) Update(context.Context, *domain.Policy) error {
	return fmt.Errorf("bundle policy repository is read-only")
}

// Delete always fails. Removing a policy is a control-plane operation; the proxy simply stops seeing it once the
// updated bundle arrives.
func (r *PolicyRepository) Delete(context.Context, string, string, bool) error {
	return fmt.Errorf("bundle policy repository is read-only")
}

// UpstreamRepository adapts tenant bundles to the core upstream repository port for the proxy runtime.
type UpstreamRepository struct {
	provider port.TenantBundleProvider
}

// NewUpstreamRepository creates a new bundle-backed upstream repository.
func NewUpstreamRepository(provider port.TenantBundleProvider) *UpstreamRepository {
	return &UpstreamRepository{provider: provider}
}

// GetByID returns one upstream from the tenant bundle.
func (r *UpstreamRepository) GetByID(ctx context.Context, tenantID, id string) (*domain.Upstream, error) {
	bundle, err := r.provider.GetTenantBundle(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	for i := range bundle.Upstreams {
		upstream := bundle.Upstreams[i]
		upstream.NormalizeScope()
		if upstream.ID == id && upstream.ScopeKind == domain.UpstreamScopeTenantShared {
			return &upstream, nil
		}
	}

	return nil, domain.ErrUpstreamNotFound
}

// GetByEcosystem returns the active upstream for the requested ecosystem from the tenant bundle.
func (r *UpstreamRepository) GetByEcosystem(
	ctx context.Context,
	tenantID string,
	eco domain.EcosystemType,
) (*domain.Upstream, error) {
	return r.ResolveVisibleByEcosystem(ctx, domain.AuthorizationScope{TenantID: tenantID}, eco)
}

// ResolveVisibleByEcosystem performs the resolve visible by ecosystem operation.
func (r *UpstreamRepository) ResolveVisibleByEcosystem(
	ctx context.Context,
	scope domain.AuthorizationScope,
	eco domain.EcosystemType,
) (*domain.Upstream, error) {
	upstreams, err := r.ListVisible(ctx, scope)
	if err != nil {
		return nil, err
	}
	var selected *domain.Upstream
	for i := range upstreams {
		if upstreams[i].Ecosystem != eco {
			continue
		}
		if selected != nil {
			return nil, domain.ErrUpstreamAmbiguous
		}
		candidate := upstreams[i]
		selected = &candidate
	}
	if selected == nil {
		return nil, domain.ErrUpstreamNotFound
	}
	return selected, nil
}

// ListByTenant returns all upstreams from the tenant bundle.
func (r *UpstreamRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error) {
	return r.ListVisible(ctx, domain.AuthorizationScope{TenantID: tenantID})
}

// GetVisibleByID performs the get visible by id operation.
func (r *UpstreamRepository) GetVisibleByID(
	ctx context.Context,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Upstream, error) {
	upstreams, err := r.ListVisible(ctx, scope)
	if err != nil {
		return nil, err
	}
	for i := range upstreams {
		if upstreams[i].ID == id {
			return &upstreams[i], nil
		}
	}
	return nil, domain.ErrUpstreamNotFound
}

// ListVisible performs the list visible operation.
func (r *UpstreamRepository) ListVisible(
	ctx context.Context,
	scope domain.AuthorizationScope,
) ([]domain.Upstream, error) {
	bundle, err := r.provider.GetTenantBundle(ctx, scope.TenantID)
	if err != nil {
		return nil, err
	}

	upstreams := make([]domain.Upstream, 0, len(bundle.Upstreams))
	for i := range bundle.Upstreams {
		upstream := bundle.Upstreams[i]
		upstream.NormalizeScope()
		if upstreamVisible(upstream, scope) {
			upstreams = append(upstreams, upstream)
		}
	}
	return upstreams, nil
}

func upstreamVisible(upstream domain.Upstream, scope domain.AuthorizationScope) bool {
	switch upstream.ScopeKind {
	case domain.UpstreamScopeTenantShared:
		return true
	case domain.UpstreamScopeOrganizationShared:
		return upstream.OrganizationID == scope.OrganizationID
	case domain.UpstreamScopeTeamLocal:
		return upstream.OrganizationID == scope.OrganizationID && upstream.TeamID == scope.TeamID
	default:
		return false
	}
}

// Create always fails. Upstreams are registered in the control plane; the proxy only reads the ones its tenant bundle
// advertises.
func (r *UpstreamRepository) Create(context.Context, *domain.Upstream) error {
	return fmt.Errorf("bundle upstream repository is read-only")
}

// Update always fails. Changing an upstream, including its capability profile and credentials, must happen in the
// control plane so scoped-policy compatibility can be validated.
func (r *UpstreamRepository) Update(context.Context, *domain.Upstream) error {
	return fmt.Errorf("bundle upstream repository is read-only")
}

// Delete always fails. Removing an upstream is a control-plane operation, and the proxy observes the removal through a
// refreshed bundle.
func (r *UpstreamRepository) Delete(context.Context, string, string) error {
	return fmt.Errorf("bundle upstream repository is read-only")
}
