package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// ResourceAuthorizer checks one permission against an explicit operational scope.
type ResourceAuthorizer interface {
	Authorize(context.Context, domain.AuthenticatedPrincipal, domain.Permission, domain.AuthorizationScope) error
}

// ScopedPolicyService applies authorization and immutable ownership to policy workflows.
type ScopedPolicyService struct {
	base       *PolicyService
	repository port.ScopedPolicyRepository
	authorizer ResourceAuthorizer
}

// NewScopedPolicyService creates an authorization-enforcing policy service.
func NewScopedPolicyService(
	base *PolicyService,
	repository port.ScopedPolicyRepository,
	authorizer ResourceAuthorizer,
) *ScopedPolicyService {
	return &ScopedPolicyService{base: base, repository: repository, authorizer: authorizer}
}

// ListAccount performs the list account operation.
func (s *ScopedPolicyService) ListAccount(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
) ([]domain.Policy, error) {
	if err := s.authorize(
		ctx,
		principal,
		domain.PermissionPoliciesRead,
		domain.AuthorizationScope{TenantID: principal.TenantID},
	); err != nil {
		return nil, err
	}
	return s.repository.ListAccount(ctx, principal.TenantID)
}

// ListOrganization performs the list organization operation.
func (s *ScopedPolicyService) ListOrganization(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	organizationID string,
) ([]domain.Policy, error) {
	if organizationID == "" {
		return nil, domain.ErrOrganizationNotFound
	}
	scope := domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}
	if err := s.authorize(ctx, principal, domain.PermissionPoliciesRead, scope); err != nil {
		return nil, err
	}
	return s.repository.ListByOrganization(ctx, principal.TenantID, organizationID)
}

// CreateAccount performs the create account operation.
func (s *ScopedPolicyService) CreateAccount(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	policy *domain.Policy,
) error {
	scope := domain.AuthorizationScope{TenantID: principal.TenantID}
	if err := s.authorize(ctx, principal, domain.PermissionPoliciesWrite, scope); err != nil {
		return err
	}
	setPolicyOwnership(policy, principal.TenantID, "")
	return s.base.Create(ctx, policy)
}

// CreateOrganization performs the create organization operation.
func (s *ScopedPolicyService) CreateOrganization(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	organizationID string,
	policy *domain.Policy,
) error {
	if organizationID == "" {
		return domain.ErrOrganizationNotFound
	}
	scope := domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID}
	if err := s.authorize(ctx, principal, domain.PermissionPoliciesWrite, scope); err != nil {
		return err
	}
	setPolicyOwnership(policy, principal.TenantID, organizationID)
	return s.base.Create(ctx, policy)
}

// GetAccount performs the get account operation.
func (s *ScopedPolicyService) GetAccount(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	id string,
) (*domain.Policy, error) {
	return s.get(
		ctx,
		principal,
		domain.PermissionPoliciesRead,
		domain.AuthorizationScope{TenantID: principal.TenantID},
		id,
	)
}

// GetOrganization performs the get organization operation.
func (s *ScopedPolicyService) GetOrganization(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	organizationID, id string,
) (*domain.Policy, error) {
	if organizationID == "" {
		return nil, domain.ErrOrganizationNotFound
	}
	return s.get(
		ctx,
		principal,
		domain.PermissionPoliciesRead,
		domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID},
		id,
	)
}

// UpdateAccount performs the update account operation.
func (s *ScopedPolicyService) UpdateAccount(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	policy *domain.Policy,
) error {
	return s.update(ctx, principal, domain.AuthorizationScope{TenantID: principal.TenantID}, policy)
}

// UpdateOrganization performs the update organization operation.
func (s *ScopedPolicyService) UpdateOrganization(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	organizationID string,
	policy *domain.Policy,
) error {
	if organizationID == "" {
		return domain.ErrOrganizationNotFound
	}
	return s.update(
		ctx,
		principal,
		domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID},
		policy,
	)
}

// DeleteAccount performs the delete account operation.
func (s *ScopedPolicyService) DeleteAccount(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	id string,
	force bool,
) error {
	return s.delete(ctx, principal, domain.AuthorizationScope{TenantID: principal.TenantID}, id, force)
}

// DeleteOrganization performs the delete organization operation.
func (s *ScopedPolicyService) DeleteOrganization(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	organizationID, id string,
	force bool,
) error {
	if organizationID == "" {
		return domain.ErrOrganizationNotFound
	}
	return s.delete(
		ctx,
		principal,
		domain.AuthorizationScope{TenantID: principal.TenantID, OrganizationID: organizationID},
		id,
		force,
	)
}

// ListVersions performs the list versions operation.
func (s *ScopedPolicyService) ListVersions(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	id string,
) ([]domain.PolicyVersion, error) {
	if _, err := s.get(ctx, principal, domain.PermissionPoliciesRead, scope, id); err != nil {
		return nil, err
	}
	return s.base.ListVersions(ctx, principal.TenantID, id)
}

// Rollback performs the rollback operation.
func (s *ScopedPolicyService) Rollback(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	id string,
	version int,
) (*domain.Policy, error) {
	if _, err := s.get(ctx, principal, domain.PermissionPoliciesWrite, scope, id); err != nil {
		return nil, err
	}
	return s.base.RollbackToVersion(ctx, principal.TenantID, id, version)
}

func (s *ScopedPolicyService) get(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	permission domain.Permission,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Policy, error) {
	if err := s.authorize(ctx, principal, permission, scope); err != nil {
		return nil, err
	}
	policy, err := s.repository.GetEffectiveByID(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if !policyOwnedByScope(*policy, scope) {
		return nil, domain.ErrPolicyNotFound
	}
	return policy, nil
}

func (s *ScopedPolicyService) update(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	policy *domain.Policy,
) error {
	if _, err := s.get(ctx, principal, domain.PermissionPoliciesWrite, scope, policy.ID); err != nil {
		return err
	}
	setPolicyOwnership(policy, principal.TenantID, scope.OrganizationID)
	return s.base.Update(ctx, policy)
}

func (s *ScopedPolicyService) delete(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	id string,
	force bool,
) error {
	if _, err := s.get(ctx, principal, domain.PermissionPoliciesDelete, scope, id); err != nil {
		return err
	}
	return s.base.Delete(ctx, principal.TenantID, id, force)
}

func (s *ScopedPolicyService) authorize(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	permission domain.Permission,
	scope domain.AuthorizationScope,
) error {
	if s == nil || s.base == nil || s.repository == nil || s.authorizer == nil {
		return fmt.Errorf("scoped policy service is not configured")
	}
	return s.authorizer.Authorize(ctx, principal, permission, scope)
}

func setPolicyOwnership(policy *domain.Policy, tenantID, organizationID string) {
	policy.TenantID = tenantID
	policy.OrganizationID = organizationID
	policy.ScopeKind = domain.PolicyScopeAccount
	if organizationID != "" {
		policy.ScopeKind = domain.PolicyScopeOrganization
	}
	policy.NormalizeScope()
}

func policyOwnedByScope(policy domain.Policy, scope domain.AuthorizationScope) bool {
	policy.NormalizeScope()
	if scope.OrganizationID == "" {
		return policy.ScopeKind == domain.PolicyScopeAccount && policy.OrganizationID == ""
	}
	return policy.ScopeKind == domain.PolicyScopeOrganization && policy.OrganizationID == scope.OrganizationID
}

// ScopedUpstreamService applies authorization and immutable ownership to upstream workflows.
type ScopedUpstreamService struct {
	base       *UpstreamService
	repository port.ScopedUpstreamRepository
	authorizer ResourceAuthorizer
}

// NewScopedUpstreamService creates an authorization-enforcing upstream service.
func NewScopedUpstreamService(
	base *UpstreamService,
	repository port.ScopedUpstreamRepository,
	authorizer ResourceAuthorizer,
) *ScopedUpstreamService {
	return &ScopedUpstreamService{base: base, repository: repository, authorizer: authorizer}
}

// List performs the list operation.
func (s *ScopedUpstreamService) List(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
) ([]domain.Upstream, error) {
	if err := s.authorize(ctx, principal, domain.PermissionUpstreamsRead, scope); err != nil {
		return nil, err
	}
	visible, err := s.repository.ListVisible(ctx, scope)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Upstream, 0, len(visible))
	for _, upstream := range visible {
		if upstreamOwnedByScope(upstream, scope) {
			result = append(result, upstream)
		}
	}
	return result, nil
}

// Create performs the create operation.
func (s *ScopedUpstreamService) Create(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	upstream *domain.Upstream,
) error {
	if err := s.authorize(ctx, principal, domain.PermissionUpstreamsWrite, scope); err != nil {
		return err
	}
	setUpstreamOwnership(upstream, principal.TenantID, scope.OrganizationID, scope.TeamID)
	return s.base.Create(ctx, upstream)
}

// Get performs the get operation.
func (s *ScopedUpstreamService) Get(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Upstream, error) {
	return s.get(ctx, principal, domain.PermissionUpstreamsRead, scope, id)
}

// Update performs the update operation.
func (s *ScopedUpstreamService) Update(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	upstream *domain.Upstream,
) error {
	if _, err := s.get(ctx, principal, domain.PermissionUpstreamsWrite, scope, upstream.ID); err != nil {
		return err
	}
	setUpstreamOwnership(upstream, principal.TenantID, scope.OrganizationID, scope.TeamID)
	return s.base.Update(ctx, upstream)
}

// Delete performs the delete operation.
func (s *ScopedUpstreamService) Delete(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	scope domain.AuthorizationScope,
	id string,
) error {
	if _, err := s.get(ctx, principal, domain.PermissionUpstreamsDelete, scope, id); err != nil {
		return err
	}
	return s.base.Delete(ctx, principal.TenantID, id)
}

func (s *ScopedUpstreamService) get(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	permission domain.Permission,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Upstream, error) {
	if err := s.authorize(ctx, principal, permission, scope); err != nil {
		return nil, err
	}
	upstream, err := s.repository.GetVisibleByID(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if !upstreamOwnedByScope(*upstream, scope) {
		return nil, domain.ErrUpstreamNotFound
	}
	return upstream, nil
}

func (s *ScopedUpstreamService) authorize(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	permission domain.Permission,
	scope domain.AuthorizationScope,
) error {
	if s == nil || s.base == nil || s.repository == nil || s.authorizer == nil {
		return fmt.Errorf("scoped upstream service is not configured")
	}
	return s.authorizer.Authorize(ctx, principal, permission, scope)
}

func setUpstreamOwnership(upstream *domain.Upstream, tenantID, organizationID, teamID string) {
	upstream.TenantID = tenantID
	upstream.OrganizationID = organizationID
	upstream.TeamID = teamID
	upstream.ScopeKind = domain.UpstreamScopeTenantShared
	if organizationID != "" {
		upstream.ScopeKind = domain.UpstreamScopeOrganizationShared
	}
	if teamID != "" {
		upstream.ScopeKind = domain.UpstreamScopeTeamLocal
	}
}

func upstreamOwnedByScope(upstream domain.Upstream, scope domain.AuthorizationScope) bool {
	upstream.NormalizeScope()
	switch {
	case scope.OrganizationID == "" && scope.TeamID == "":
		return upstream.ScopeKind == domain.UpstreamScopeTenantShared && upstream.OrganizationID == "" &&
			upstream.TeamID == ""
	case scope.TeamID == "":
		return upstream.ScopeKind == domain.UpstreamScopeOrganizationShared &&
			upstream.OrganizationID == scope.OrganizationID &&
			upstream.TeamID == ""
	default:
		return upstream.ScopeKind == domain.UpstreamScopeTeamLocal && upstream.OrganizationID == scope.OrganizationID &&
			upstream.TeamID == scope.TeamID
	}
}
