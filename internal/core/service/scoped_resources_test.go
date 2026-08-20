package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type authorizationCall struct {
	permission domain.Permission
	scope      domain.AuthorizationScope
}

type recordingResourceAuthorizer struct {
	calls []authorizationCall
	err   error
}

func (a *recordingResourceAuthorizer) Authorize(
	_ context.Context,
	_ domain.AuthenticatedPrincipal,
	permission domain.Permission,
	scope domain.AuthorizationScope,
) error {
	a.calls = append(a.calls, authorizationCall{permission: permission, scope: scope})
	return a.err
}

type memoryScopedPolicyRepository struct{ *spyPolicyServiceRepo }

func (r *memoryScopedPolicyRepository) ListAccount(_ context.Context, tenantID string) ([]domain.Policy, error) {
	result := []domain.Policy{}
	for _, policy := range r.listPolicies {
		if policy.TenantID == tenantID && policyOwnedByScope(policy, domain.AuthorizationScope{TenantID: tenantID}) {
			result = append(result, policy)
		}
	}
	return result, nil
}

func (r *memoryScopedPolicyRepository) ListByOrganization(
	_ context.Context,
	tenantID, organizationID string,
) ([]domain.Policy, error) {
	result := []domain.Policy{}
	for _, policy := range r.listPolicies {
		if policy.TenantID == tenantID &&
			policyOwnedByScope(policy, domain.AuthorizationScope{TenantID: tenantID, OrganizationID: organizationID}) {
			result = append(result, policy)
		}
	}
	return result, nil
}

func (r *memoryScopedPolicyRepository) ListEffective(
	ctx context.Context,
	scope domain.AuthorizationScope,
) ([]domain.Policy, error) {
	account, _ := r.ListAccount(ctx, scope.TenantID)
	organization, _ := r.ListByOrganization(ctx, scope.TenantID, scope.OrganizationID)
	return append(account, organization...), nil
}

func (r *memoryScopedPolicyRepository) GetEffectiveByID(
	ctx context.Context,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Policy, error) {
	policies, _ := r.ListEffective(ctx, scope)
	for i := range policies {
		if policies[i].ID == id {
			return &policies[i], nil
		}
	}
	return nil, domain.ErrPolicyNotFound
}

func TestScopedPolicyService_SetsOwnershipAndRejectsInheritedMutation(t *testing.T) {
	repository := &memoryScopedPolicyRepository{spyPolicyServiceRepo: &spyPolicyServiceRepo{}}
	authorizer := &recordingResourceAuthorizer{}
	base := NewPolicyService(repository, &spyPolicyRevisionRepository{}, &spyPolicyDecisionCache{}, nil)
	service := NewScopedPolicyService(base, repository, authorizer)
	principal := domain.AuthenticatedPrincipal{
		Principal:  domain.Principal{ID: "principal-1"},
		TenantID:   "tenant-1",
		TenantRole: domain.TenantRoleAdmin,
	}

	organizationPolicy := &domain.Policy{
		Name:          "deny-high-cvss",
		Type:          domain.PolicyTypeCVSSThreshold,
		Action:        domain.PolicyActionDeny,
		SchemaVersion: 1,
		Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7)},
		Enabled:       true,
	}
	require.NoError(
		t,
		service.CreateOrganization(context.Background(), principal, "organization-1", organizationPolicy),
	)
	assert.Equal(t, "tenant-1", organizationPolicy.TenantID)
	assert.Equal(t, "organization-1", organizationPolicy.OrganizationID)
	assert.Equal(t, domain.PolicyScopeOrganization, organizationPolicy.ScopeKind)
	assert.Equal(t, domain.PolicyWaiverApprovalRequired, organizationPolicy.WaiverMode)
	assert.Equal(t, domain.PermissionPoliciesWrite, authorizer.calls[0].permission)
	assert.Equal(t, "organization-1", authorizer.calls[0].scope.OrganizationID)

	_, err := service.GetAccount(context.Background(), principal, organizationPolicy.ID)
	require.ErrorIs(t, err, domain.ErrPolicyNotFound)
}

func TestScopedPolicyService_DenialPreventsMutation(t *testing.T) {
	repository := &memoryScopedPolicyRepository{spyPolicyServiceRepo: &spyPolicyServiceRepo{}}
	authorizer := &recordingResourceAuthorizer{
		err: &domain.AuthorizationError{Reason: domain.AuthorizationDenialInsufficientPermission},
	}
	base := NewPolicyService(repository, &spyPolicyRevisionRepository{}, &spyPolicyDecisionCache{}, nil)
	service := NewScopedPolicyService(base, repository, authorizer)
	principal := domain.AuthenticatedPrincipal{
		Principal:  domain.Principal{ID: "principal-1"},
		TenantID:   "tenant-1",
		TenantRole: domain.TenantRoleMember,
	}
	policy := &domain.Policy{
		Name:          "deny",
		Type:          domain.PolicyTypeCVSSThreshold,
		Action:        domain.PolicyActionDeny,
		SchemaVersion: 1,
		Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7)},
		Enabled:       true,
	}

	err := service.CreateAccount(context.Background(), principal, policy)

	require.Error(t, err)
	var denial *domain.AuthorizationError
	require.ErrorAs(t, err, &denial)
	assert.Zero(t, repository.createCalls)
}

type memoryScopedUpstreamRepository struct {
	items []domain.Upstream
}

func (r *memoryScopedUpstreamRepository) GetByID(_ context.Context, tenantID, id string) (*domain.Upstream, error) {
	for i := range r.items {
		if r.items[i].TenantID == tenantID && r.items[i].ID == id {
			copyUpstream := r.items[i]
			return &copyUpstream, nil
		}
	}
	return nil, domain.ErrUpstreamNotFound
}

func (r *memoryScopedUpstreamRepository) GetByEcosystem(
	context.Context,
	string,
	domain.EcosystemType,
) (*domain.Upstream, error) {
	return nil, domain.ErrUpstreamNotFound
}

func (r *memoryScopedUpstreamRepository) ListByTenant(_ context.Context, tenantID string) ([]domain.Upstream, error) {
	result := []domain.Upstream{}
	for _, upstream := range r.items {
		if upstream.TenantID == tenantID {
			result = append(result, upstream)
		}
	}
	return result, nil
}

func (r *memoryScopedUpstreamRepository) Create(_ context.Context, upstream *domain.Upstream) error {
	upstream.ID = "created-upstream"
	r.items = append(r.items, *upstream)
	return nil
}

func (r *memoryScopedUpstreamRepository) Update(_ context.Context, upstream *domain.Upstream) error {
	for i := range r.items {
		if r.items[i].TenantID == upstream.TenantID && r.items[i].ID == upstream.ID &&
			upstreamOwnedByScope(
				r.items[i],
				domain.AuthorizationScope{
					TenantID:       upstream.TenantID,
					OrganizationID: upstream.OrganizationID,
					TeamID:         upstream.TeamID,
				},
			) {
			r.items[i] = *upstream
			return nil
		}
	}
	return domain.ErrUpstreamNotFound
}

func (r *memoryScopedUpstreamRepository) Delete(_ context.Context, tenantID, id string) error {
	for i := range r.items {
		if r.items[i].TenantID == tenantID && r.items[i].ID == id {
			r.items = append(r.items[:i], r.items[i+1:]...)
			return nil
		}
	}
	return domain.ErrUpstreamNotFound
}

func (r *memoryScopedUpstreamRepository) GetVisibleByID(
	ctx context.Context,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Upstream, error) {
	visible, _ := r.ListVisible(ctx, scope)
	for i := range visible {
		if visible[i].ID == id {
			return &visible[i], nil
		}
	}
	return nil, domain.ErrUpstreamNotFound
}

func (r *memoryScopedUpstreamRepository) ListVisible(
	_ context.Context,
	scope domain.AuthorizationScope,
) ([]domain.Upstream, error) {
	result := []domain.Upstream{}
	for _, upstream := range r.items {
		upstream.NormalizeScope()
		if upstream.TenantID != scope.TenantID {
			continue
		}
		if upstream.ScopeKind == domain.UpstreamScopeTenantShared ||
			(upstream.ScopeKind == domain.UpstreamScopeOrganizationShared && upstream.OrganizationID == scope.OrganizationID) ||
			(upstream.ScopeKind == domain.UpstreamScopeTeamLocal && upstream.OrganizationID == scope.OrganizationID && upstream.TeamID == scope.TeamID) {
			result = append(result, upstream)
		}
	}
	return result, nil
}

func (r *memoryScopedUpstreamRepository) ResolveVisibleByEcosystem(
	context.Context,
	domain.AuthorizationScope,
	domain.EcosystemType,
) (*domain.Upstream, error) {
	return nil, domain.ErrUpstreamNotFound
}

func TestScopedUpstreamService_ListsOnlyOwnedScope(t *testing.T) {
	repository := &memoryScopedUpstreamRepository{items: []domain.Upstream{
		{ID: "tenant", TenantID: "tenant-1", ScopeKind: domain.UpstreamScopeTenantShared},
		{
			ID:             "organization",
			TenantID:       "tenant-1",
			OrganizationID: "organization-1",
			ScopeKind:      domain.UpstreamScopeOrganizationShared,
		},
		{
			ID:             "team",
			TenantID:       "tenant-1",
			OrganizationID: "organization-1",
			TeamID:         "team-1",
			ScopeKind:      domain.UpstreamScopeTeamLocal,
		},
	}}
	authorizer := &recordingResourceAuthorizer{}
	service := NewScopedUpstreamService(NewUpstreamService(repository, nil), repository, authorizer)
	principal := domain.AuthenticatedPrincipal{
		Principal:  domain.Principal{ID: "principal-1"},
		TenantID:   "tenant-1",
		TenantRole: domain.TenantRoleAdmin,
	}

	organization, err := service.List(
		context.Background(),
		principal,
		domain.AuthorizationScope{TenantID: "tenant-1", OrganizationID: "organization-1"},
	)
	require.NoError(t, err)
	require.Len(t, organization, 1)
	assert.Equal(t, "organization", organization[0].ID)

	team, err := service.List(
		context.Background(),
		principal,
		domain.AuthorizationScope{TenantID: "tenant-1", OrganizationID: "organization-1", TeamID: "team-1"},
	)
	require.NoError(t, err)
	require.Len(t, team, 1)
	assert.Equal(t, "team", team[0].ID)
}
