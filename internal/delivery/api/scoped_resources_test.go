package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

func (m *mockPolicyRepo) ListAccount(ctx context.Context, tenantID string) ([]domain.Policy, error) {
	policies, err := m.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	result := []domain.Policy{}
	for _, policy := range policies {
		policy.NormalizeScope()
		if policy.ScopeKind == domain.PolicyScopeAccount {
			result = append(result, policy)
		}
	}
	return result, nil
}

func (m *mockPolicyRepo) ListByOrganization(
	ctx context.Context,
	tenantID, organizationID string,
) ([]domain.Policy, error) {
	policies, err := m.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	result := []domain.Policy{}
	for _, policy := range policies {
		policy.NormalizeScope()
		if policy.ScopeKind == domain.PolicyScopeOrganization && policy.OrganizationID == organizationID {
			result = append(result, policy)
		}
	}
	return result, nil
}

func (m *mockPolicyRepo) ListEffective(ctx context.Context, scope domain.AuthorizationScope) ([]domain.Policy, error) {
	account, err := m.ListAccount(ctx, scope.TenantID)
	if err != nil {
		return nil, err
	}
	if scope.OrganizationID == "" {
		return account, nil
	}
	organization, err := m.ListByOrganization(ctx, scope.TenantID, scope.OrganizationID)
	if err != nil {
		return nil, err
	}
	return append(account, organization...), nil
}

func (m *mockPolicyRepo) GetEffectiveByID(
	ctx context.Context,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Policy, error) {
	policies, err := m.ListEffective(ctx, scope)
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

func (m *mockUpstreamRepo) ListVisible(
	ctx context.Context,
	scope domain.AuthorizationScope,
) ([]domain.Upstream, error) {
	upstreams, err := m.ListByTenant(ctx, scope.TenantID)
	if err != nil {
		return nil, err
	}
	result := []domain.Upstream{}
	for _, upstream := range upstreams {
		upstream.NormalizeScope()
		if upstream.ScopeKind == domain.UpstreamScopeTenantShared ||
			(upstream.ScopeKind == domain.UpstreamScopeOrganizationShared && upstream.OrganizationID == scope.OrganizationID) ||
			(upstream.ScopeKind == domain.UpstreamScopeTeamLocal && upstream.OrganizationID == scope.OrganizationID && upstream.TeamID == scope.TeamID) {
			result = append(result, upstream)
		}
	}
	return result, nil
}

func (m *mockUpstreamRepo) GetVisibleByID(
	ctx context.Context,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Upstream, error) {
	upstreams, err := m.ListVisible(ctx, scope)
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

func (m *mockUpstreamRepo) ResolveVisibleByEcosystem(
	ctx context.Context,
	scope domain.AuthorizationScope,
	ecosystem domain.EcosystemType,
) (*domain.Upstream, error) {
	upstreams, err := m.ListVisible(ctx, scope)
	if err != nil {
		return nil, err
	}
	var match *domain.Upstream
	for i := range upstreams {
		if upstreams[i].Ecosystem != ecosystem {
			continue
		}
		if match != nil {
			return nil, domain.ErrUpstreamAmbiguous
		}
		copyUpstream := upstreams[i]
		match = &copyUpstream
	}
	if match == nil {
		return nil, domain.ErrUpstreamNotFound
	}
	return match, nil
}

type scopedAPIAuthenticator struct{}

func (scopedAPIAuthenticator) Authenticate(context.Context, string) (domain.VerifiedIdentity, error) {
	return domain.VerifiedIdentity{
		Provider:          "test",
		Subject:           "user-1",
		ExternalAccountID: "account-1",
		TenantRole:        domain.TenantRoleAdmin,
	}, nil
}

type scopedAPIResolver struct{ principal domain.AuthenticatedPrincipal }

func (r scopedAPIResolver) Resolve(context.Context, domain.VerifiedIdentity) (domain.AuthenticatedPrincipal, error) {
	return r.principal, nil
}

type scopedAPIAuthorizer struct{}

func (scopedAPIAuthorizer) Authorize(
	context.Context,
	domain.AuthenticatedPrincipal,
	domain.Permission,
	domain.AuthorizationScope,
) error {
	return nil
}

type scopedAPIMembershipVerifier struct{}

func (scopedAPIMembershipVerifier) FreshTenantRole(
	context.Context,
	domain.VerifiedIdentity,
) (domain.TenantRole, error) {
	return domain.TenantRoleAdmin, nil
}

func TestScopedResourceRoutes_DeriveTenantAndHideOtherOwnershipScopes(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	upstreamRepo := newMockUpstreamRepo()
	decisionCache := &mockDecisionCache{}
	authorizer := scopedAPIAuthorizer{}
	policyBase := service.NewPolicyService(policyRepo, &mockPolicyRevisionRepo{}, decisionCache, upstreamRepo)
	upstreamBase := service.NewUpstreamService(upstreamRepo, policyRepo)
	handler := NewScopedResourceHandler(
		service.NewScopedPolicyService(policyBase, policyRepo, authorizer),
		service.NewScopedUpstreamService(upstreamBase, upstreamRepo, authorizer),
		slogForTest(),
	)

	mux := http.NewServeMux()
	api := NewControlPlaneAPI(mux, "test")
	principal := domain.AuthenticatedPrincipal{
		Principal:  domain.Principal{ID: "principal-1", Status: domain.PrincipalStatusActive},
		TenantID:   "tenant-1",
		TenantRole: domain.TenantRoleAdmin,
	}
	api.UseMiddleware(
		middleware.HumanAuthentication(
			api,
			scopedAPIAuthenticator{},
			scopedAPIResolver{principal: principal},
			authorizer,
			scopedAPIMembershipVerifier{},
			func(operationID string) (middleware.HumanOperationPolicy, bool) {
				policy, ok := ControlPlaneOperationPolicy(operationID)
				return middleware.HumanOperationPolicy{
					AuthenticationRequired: policy.AuthenticationRequired,
					Permission:             policy.Permission,
					Bootstrap:              policy.Bootstrap,
					FreshMembership:        policy.FreshMembership,
					ScopedAuthorization:    policy.ScopedAuthorization,
				}, ok
			},
		),
	)
	handler.RegisterHumaRoutes(api)

	policyPath := "/api/v1/organizations/organization-1/policies"
	forgedPolicy := serveScopedRequest(t, mux, http.MethodPost, policyPath, map[string]any{
		"tenant_id":      "forged-tenant",
		"name":           "deny-high-cvss",
		"type":           "cvss_threshold",
		"action":         "deny",
		"schema_version": 1,
		"config":         map[string]any{"max_cvss": 7.0},
		"enabled":        true,
	})
	assert.Equal(t, http.StatusBadRequest, forgedPolicy.Code)
	policyResponse := serveScopedJSON[PolicyResponse](t, mux, http.MethodPost, policyPath, map[string]any{
		"name":           "deny-high-cvss",
		"type":           "cvss_threshold",
		"action":         "deny",
		"schema_version": 1,
		"config":         map[string]any{"max_cvss": 7.0},
		"enabled":        true,
	}, http.StatusCreated)
	assert.Equal(t, "tenant-1", policyResponse.TenantID)
	assert.Equal(t, "organization-1", policyResponse.OrganizationID)
	assert.Equal(t, domain.PolicyScopeOrganization, policyResponse.Scope)
	assert.Equal(t, domain.PolicyWaiverApprovalRequired, policyResponse.WaiverMode)
	updatedPolicy := serveScopedJSON[PolicyResponse](
		t,
		mux,
		http.MethodPut,
		policyPath+"/"+policyResponse.ID,
		map[string]any{
			"name":           "deny-critical-cvss",
			"type":           "cvss_threshold",
			"action":         "deny",
			"schema_version": 1,
			"config":         map[string]any{"max_cvss": 9.0},
			"enabled":        true,
		},
		http.StatusOK,
	)
	assert.Equal(t, "deny-critical-cvss", updatedPolicy.Name)
	assert.Equal(t, "organization-1", updatedPolicy.OrganizationID)
	assert.Equal(t, domain.PolicyScopeOrganization, updatedPolicy.Scope)

	accountLookup := serveScopedRequest(t, mux, http.MethodGet, "/api/v1/account/policies/"+policyResponse.ID, nil)
	assert.Equal(t, http.StatusNotFound, accountLookup.Code)

	teamUpstreamPath := "/api/v1/organizations/organization-1/teams/team-1/upstreams"
	forgedUpstream := serveScopedRequest(t, mux, http.MethodPost, teamUpstreamPath, map[string]any{
		"name":      "team-npm",
		"ecosystem": "npm",
		"base_url":  "https://registry.example.test",
		"tenant_id": "forged-tenant",
		"team_id":   "forged-team",
	})
	assert.Equal(t, http.StatusBadRequest, forgedUpstream.Code)
	teamUpstream := serveScopedJSON[UpstreamResponse](t, mux, http.MethodPost, teamUpstreamPath, map[string]any{
		"name":      "team-npm",
		"ecosystem": "npm",
		"base_url":  "https://registry.example.test",
	}, http.StatusCreated)
	assert.Equal(t, "tenant-1", teamUpstream.TenantID)
	assert.Equal(t, "organization-1", teamUpstream.OrganizationID)
	assert.Equal(t, "team-1", teamUpstream.TeamID)
	assert.Equal(t, domain.UpstreamScopeTeamLocal, teamUpstream.Scope)
	updatedUpstream := serveScopedJSON[UpstreamResponse](
		t,
		mux,
		http.MethodPut,
		teamUpstreamPath+"/"+teamUpstream.ID,
		map[string]any{
			"name":      "team-npm-mirror",
			"ecosystem": "npm",
			"base_url":  "https://mirror.example.test",
		},
		http.StatusOK,
	)
	assert.Equal(t, "team-npm-mirror", updatedUpstream.Name)
	assert.Equal(t, "team-1", updatedUpstream.TeamID)
	assert.Equal(t, domain.UpstreamScopeTeamLocal, updatedUpstream.Scope)

	organizationUpstreams := serveScopedJSON[[]UpstreamResponse](
		t,
		mux,
		http.MethodGet,
		"/api/v1/organizations/organization-1/upstreams",
		nil,
		http.StatusOK,
	)
	assert.Empty(t, organizationUpstreams)
	wrongTeam := serveScopedRequest(
		t,
		mux,
		http.MethodGet,
		"/api/v1/organizations/organization-1/teams/team-2/upstreams/"+teamUpstream.ID,
		nil,
	)
	assert.Equal(t, http.StatusNotFound, wrongTeam.Code)
}

func serveScopedJSON[T any](t *testing.T, mux http.Handler, method, path string, body any, expectedStatus int) T {
	t.Helper()
	response := serveScopedRequest(t, mux, method, path, body)
	require.Equal(t, expectedStatus, response.Code, response.Body.String())
	var result T
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	return result
}

func serveScopedRequest(t *testing.T, mux http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&requestBody).Encode(body))
	}
	request := httptest.NewRequest(method, path, &requestBody)
	request.Header.Set("Authorization", "Bearer test-token")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}

func slogForTest() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
