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
		if bundle.Policies[i].ID == id {
			policyDef := bundle.Policies[i]
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

	policies := make([]domain.Policy, len(bundle.Policies))
	copy(policies, bundle.Policies)
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
		if bundle.Upstreams[i].ID == id {
			upstream := bundle.Upstreams[i]
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
	bundle, err := r.provider.GetTenantBundle(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var selected *domain.Upstream
	for i := range bundle.Upstreams {
		if bundle.Upstreams[i].Ecosystem != eco {
			continue
		}
		if selected == nil || bundle.Upstreams[i].UpdatedAt.After(selected.UpdatedAt) {
			candidate := bundle.Upstreams[i]
			selected = &candidate
		}
	}
	if selected == nil {
		return nil, domain.ErrUpstreamNotFound
	}
	return selected, nil
}

// ListByTenant returns all upstreams from the tenant bundle.
func (r *UpstreamRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error) {
	bundle, err := r.provider.GetTenantBundle(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	upstreams := make([]domain.Upstream, len(bundle.Upstreams))
	copy(upstreams, bundle.Upstreams)
	return upstreams, nil
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
