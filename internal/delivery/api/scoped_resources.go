package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// ScopedResourceHandler exposes account, Organization, and Team-owned resources.
type ScopedResourceHandler struct {
	policies  *service.ScopedPolicyService
	upstreams *service.ScopedUpstreamService
	logger    *slog.Logger
}

// NewScopedResourceHandler creates a scoped resource API handler.
func NewScopedResourceHandler(policies *service.ScopedPolicyService, upstreams *service.ScopedUpstreamService, logger *slog.Logger) *ScopedResourceHandler {
	return &ScopedResourceHandler{policies: policies, upstreams: upstreams, logger: logger}
}

// RegisterHumaRoutes registers scoped policy and upstream CRUD operations.
func (h *ScopedResourceHandler) RegisterHumaRoutes(api huma.API) {
	h.registerPolicyRoutes(api)
	h.registerUpstreamRoutes(api)
}

func (h *ScopedResourceHandler) registerPolicyRoutes(api huma.API) {
	huma.Register(api, scopedOperation("create-account-policy", http.MethodPost, "/api/v1/account/policies", "Create an account policy", http.StatusCreated, "policies"), h.createAccountPolicy)
	huma.Register(api, scopedOperation("list-account-policies", http.MethodGet, "/api/v1/account/policies", "List account policies", 0, "policies"), h.listAccountPolicies)
	huma.Register(api, scopedOperation("get-account-policy", http.MethodGet, "/api/v1/account/policies/{policy_id}", "Get an account policy", 0, "policies"), h.getAccountPolicy)
	huma.Register(api, scopedOperation("update-account-policy", http.MethodPut, "/api/v1/account/policies/{policy_id}", "Update an account policy", 0, "policies"), h.updateAccountPolicyWithBody)
	huma.Register(api, scopedOperation("delete-account-policy", http.MethodDelete, "/api/v1/account/policies/{policy_id}", "Delete an account policy", http.StatusNoContent, "policies"), h.deleteAccountPolicy)

	organizationPath := "/api/v1/organizations/{organization_id}/policies"
	huma.Register(api, scopedOperation("create-organization-policy", http.MethodPost, organizationPath, "Create an Organization policy", http.StatusCreated, "policies"), h.createOrganizationPolicy)
	huma.Register(api, scopedOperation("list-organization-policies", http.MethodGet, organizationPath, "List Organization policies", 0, "policies"), h.listOrganizationPolicies)
	huma.Register(api, scopedOperation("get-organization-policy", http.MethodGet, organizationPath+"/{policy_id}", "Get an Organization policy", 0, "policies"), h.getOrganizationPolicy)
	huma.Register(api, scopedOperation("update-organization-policy", http.MethodPut, organizationPath+"/{policy_id}", "Update an Organization policy", 0, "policies"), h.updateOrganizationPolicyWithBody)
	huma.Register(api, scopedOperation("delete-organization-policy", http.MethodDelete, organizationPath+"/{policy_id}", "Delete an Organization policy", http.StatusNoContent, "policies"), h.deleteOrganizationPolicy)

	removeValidationResponse(api, "/api/v1/account/policies", http.MethodGet, http.MethodPost)
	removeValidationResponse(api, "/api/v1/account/policies/{policy_id}", http.MethodGet, http.MethodPut, http.MethodDelete)
	removeValidationResponse(api, organizationPath, http.MethodGet, http.MethodPost)
	removeValidationResponse(api, organizationPath+"/{policy_id}", http.MethodGet, http.MethodPut, http.MethodDelete)
}

func (h *ScopedResourceHandler) registerUpstreamRoutes(api huma.API) {
	huma.Register(api, scopedOperation("create-account-upstream", http.MethodPost, "/api/v1/account/upstreams", "Create a Tenant-shared upstream", http.StatusCreated, "upstreams"), h.createAccountUpstream)
	huma.Register(api, scopedOperation("list-account-upstreams", http.MethodGet, "/api/v1/account/upstreams", "List Tenant-shared upstreams", 0, "upstreams"), h.listAccountUpstreams)
	huma.Register(api, scopedOperation("get-account-upstream", http.MethodGet, "/api/v1/account/upstreams/{upstream_id}", "Get a Tenant-shared upstream", 0, "upstreams"), h.getAccountUpstream)
	huma.Register(api, scopedOperation("update-account-upstream", http.MethodPut, "/api/v1/account/upstreams/{upstream_id}", "Update a Tenant-shared upstream", 0, "upstreams"), h.updateAccountUpstreamWithBody)
	huma.Register(api, scopedOperation("delete-account-upstream", http.MethodDelete, "/api/v1/account/upstreams/{upstream_id}", "Delete a Tenant-shared upstream", http.StatusNoContent, "upstreams"), h.deleteAccountUpstream)

	organizationPath := "/api/v1/organizations/{organization_id}/upstreams"
	huma.Register(api, scopedOperation("create-organization-upstream", http.MethodPost, organizationPath, "Create an Organization-shared upstream", http.StatusCreated, "upstreams"), h.createOrganizationUpstream)
	huma.Register(api, scopedOperation("list-organization-upstreams", http.MethodGet, organizationPath, "List Organization-shared upstreams", 0, "upstreams"), h.listOrganizationUpstreams)
	huma.Register(api, scopedOperation("get-organization-upstream", http.MethodGet, organizationPath+"/{upstream_id}", "Get an Organization-shared upstream", 0, "upstreams"), h.getOrganizationUpstream)
	huma.Register(api, scopedOperation("update-organization-upstream", http.MethodPut, organizationPath+"/{upstream_id}", "Update an Organization-shared upstream", 0, "upstreams"), h.updateOrganizationUpstreamWithBody)
	huma.Register(api, scopedOperation("delete-organization-upstream", http.MethodDelete, organizationPath+"/{upstream_id}", "Delete an Organization-shared upstream", http.StatusNoContent, "upstreams"), h.deleteOrganizationUpstream)

	teamPath := "/api/v1/organizations/{organization_id}/teams/{team_id}/upstreams"
	huma.Register(api, scopedOperation("create-team-upstream", http.MethodPost, teamPath, "Create a Team-local upstream", http.StatusCreated, "upstreams"), h.createTeamUpstream)
	huma.Register(api, scopedOperation("list-team-upstreams", http.MethodGet, teamPath, "List Team-local upstreams", 0, "upstreams"), h.listTeamUpstreams)
	huma.Register(api, scopedOperation("get-team-upstream", http.MethodGet, teamPath+"/{upstream_id}", "Get a Team-local upstream", 0, "upstreams"), h.getTeamUpstream)
	huma.Register(api, scopedOperation("update-team-upstream", http.MethodPut, teamPath+"/{upstream_id}", "Update a Team-local upstream", 0, "upstreams"), h.updateTeamUpstreamWithBody)
	huma.Register(api, scopedOperation("delete-team-upstream", http.MethodDelete, teamPath+"/{upstream_id}", "Delete a Team-local upstream", http.StatusNoContent, "upstreams"), h.deleteTeamUpstream)

	removeValidationResponse(api, "/api/v1/account/upstreams", http.MethodGet, http.MethodPost)
	removeValidationResponse(api, "/api/v1/account/upstreams/{upstream_id}", http.MethodGet, http.MethodPut, http.MethodDelete)
	removeValidationResponse(api, organizationPath, http.MethodGet, http.MethodPost)
	removeValidationResponse(api, organizationPath+"/{upstream_id}", http.MethodGet, http.MethodPut, http.MethodDelete)
	removeValidationResponse(api, teamPath, http.MethodGet, http.MethodPost)
	removeValidationResponse(api, teamPath+"/{upstream_id}", http.MethodGet, http.MethodPut, http.MethodDelete)
}

func scopedOperation(id, method, path, summary string, status int, tag string) huma.Operation {
	return huma.Operation{
		OperationID:   id,
		Method:        method,
		Path:          path,
		Summary:       summary,
		Description:   summary + ". Tenant ownership comes from the authenticated session; path identifiers are validated as selectors.",
		DefaultStatus: status,
		Tags:          []string{tag},
		Errors:        controlPlaneErrors(http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError),
	}
}

type accountPolicyInput struct{ Body policyRequest }
type accountPolicyIDInput struct {
	PolicyID string `path:"policy_id" doc:"Policy identifier"`
}
type deleteAccountPolicyInput struct {
	PolicyID string `path:"policy_id" doc:"Policy identifier"`
	Force    bool   `query:"force" doc:"Detach historical evaluation and decision references before deleting"`
}
type organizationPolicyInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	Body           policyRequest
}
type organizationPolicyIDInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	PolicyID       string `path:"policy_id" doc:"Policy identifier"`
}
type deleteOrganizationPolicyInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	PolicyID       string `path:"policy_id" doc:"Policy identifier"`
	Force          bool   `query:"force" doc:"Detach historical evaluation and decision references before deleting"`
}

func (h *ScopedResourceHandler) createAccountPolicy(ctx context.Context, input *accountPolicyInput) (*policyOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := policyFromScopedRequest(input.Body)
	if err != nil {
		return nil, err
	}
	if err := h.policies.CreateAccount(ctx, principal, policy); err != nil {
		return nil, h.scopedError(ctx, "creating account policy", err)
	}
	return &policyOutput{Body: toPolicyResponse(policy)}, nil
}

func (h *ScopedResourceHandler) listAccountPolicies(ctx context.Context, _ *struct{}) (*policyListOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := h.policies.ListAccount(ctx, principal)
	if err != nil {
		return nil, h.scopedError(ctx, "listing account policies", err)
	}
	return &policyListOutput{Body: toPoliciesResponse(policies)}, nil
}

func (h *ScopedResourceHandler) getAccountPolicy(ctx context.Context, input *accountPolicyIDInput) (*policyOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := h.policies.GetAccount(ctx, principal, input.PolicyID)
	if err != nil {
		return nil, h.scopedError(ctx, "getting account policy", err)
	}
	return &policyOutput{Body: toPolicyResponse(policy)}, nil
}

type updateAccountPolicyInput struct {
	PolicyID string `path:"policy_id" doc:"Policy identifier"`
	Body     policyRequest
}

func (h *ScopedResourceHandler) updateAccountPolicyWithBody(ctx context.Context, input *updateAccountPolicyInput) (*policyOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := policyFromScopedRequest(input.Body)
	if err != nil {
		return nil, err
	}
	policy.ID = input.PolicyID
	if err := h.policies.UpdateAccount(ctx, principal, policy); err != nil {
		return nil, h.scopedError(ctx, "updating account policy", err)
	}
	return &policyOutput{Body: toPolicyResponse(policy)}, nil
}

func (h *ScopedResourceHandler) deleteAccountPolicy(ctx context.Context, input *deleteAccountPolicyInput) (*struct{}, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.policies.DeleteAccount(ctx, principal, input.PolicyID, input.Force); err != nil {
		return nil, h.scopedError(ctx, "deleting account policy", err)
	}
	return nil, nil
}

func (h *ScopedResourceHandler) createOrganizationPolicy(ctx context.Context, input *organizationPolicyInput) (*policyOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := policyFromScopedRequest(input.Body)
	if err != nil {
		return nil, err
	}
	if err := h.policies.CreateOrganization(ctx, principal, input.OrganizationID, policy); err != nil {
		return nil, h.scopedError(ctx, "creating Organization policy", err)
	}
	return &policyOutput{Body: toPolicyResponse(policy)}, nil
}

func (h *ScopedResourceHandler) listOrganizationPolicies(ctx context.Context, input *organizationPathInput) (*policyListOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := h.policies.ListOrganization(ctx, principal, input.OrganizationID)
	if err != nil {
		return nil, h.scopedError(ctx, "listing Organization policies", err)
	}
	return &policyListOutput{Body: toPoliciesResponse(policies)}, nil
}

func (h *ScopedResourceHandler) getOrganizationPolicy(ctx context.Context, input *organizationPolicyIDInput) (*policyOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := h.policies.GetOrganization(ctx, principal, input.OrganizationID, input.PolicyID)
	if err != nil {
		return nil, h.scopedError(ctx, "getting Organization policy", err)
	}
	return &policyOutput{Body: toPolicyResponse(policy)}, nil
}

type updateOrganizationPolicyInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	PolicyID       string `path:"policy_id" doc:"Policy identifier"`
	Body           policyRequest
}

func (h *ScopedResourceHandler) updateOrganizationPolicyWithBody(ctx context.Context, input *updateOrganizationPolicyInput) (*policyOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := policyFromScopedRequest(input.Body)
	if err != nil {
		return nil, err
	}
	policy.ID = input.PolicyID
	if err := h.policies.UpdateOrganization(ctx, principal, input.OrganizationID, policy); err != nil {
		return nil, h.scopedError(ctx, "updating Organization policy", err)
	}
	return &policyOutput{Body: toPolicyResponse(policy)}, nil
}

func (h *ScopedResourceHandler) deleteOrganizationPolicy(ctx context.Context, input *deleteOrganizationPolicyInput) (*struct{}, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.policies.DeleteOrganization(ctx, principal, input.OrganizationID, input.PolicyID, input.Force); err != nil {
		return nil, h.scopedError(ctx, "deleting Organization policy", err)
	}
	return nil, nil
}

func policyFromScopedRequest(req policyRequest) (*domain.Policy, error) {
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if err := req.Target.Validate(); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if req.Target != nil {
		req.Target.Normalize()
	}
	config, err := corepolicy.DecodeConfigJSON(req.Type, req.SchemaVersion, req.Config)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	return &domain.Policy{WaiverMode: req.WaiverMode, UpstreamID: trimOptionalString(req.UpstreamID), Name: req.Name, Type: req.Type, Action: req.Action, SchemaVersion: req.SchemaVersion, Target: req.Target, Config: config, Priority: req.Priority, Enabled: req.Enabled}, nil
}

type accountUpstreamInput struct{ Body createUpstreamRequest }
type organizationUpstreamInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	Body           createUpstreamRequest
}
type teamUpstreamInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	TeamID         string `path:"team_id" doc:"Team identifier"`
	Body           createUpstreamRequest
}
type accountUpstreamIDInput struct {
	UpstreamID string `path:"upstream_id" doc:"Upstream identifier"`
}
type organizationUpstreamIDInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	UpstreamID     string `path:"upstream_id" doc:"Upstream identifier"`
}
type teamUpstreamIDInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	TeamID         string `path:"team_id" doc:"Team identifier"`
	UpstreamID     string `path:"upstream_id" doc:"Upstream identifier"`
}

func (h *ScopedResourceHandler) createAccountUpstream(ctx context.Context, input *accountUpstreamInput) (*upstreamOutput, error) {
	return h.createScopedUpstream(ctx, domain.AuthorizationScope{}, input.Body)
}
func (h *ScopedResourceHandler) createOrganizationUpstream(ctx context.Context, input *organizationUpstreamInput) (*upstreamOutput, error) {
	return h.createScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID}, input.Body)
}
func (h *ScopedResourceHandler) createTeamUpstream(ctx context.Context, input *teamUpstreamInput) (*upstreamOutput, error) {
	return h.createScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID, TeamID: input.TeamID}, input.Body)
}
func (h *ScopedResourceHandler) listAccountUpstreams(ctx context.Context, _ *struct{}) (*upstreamListOutput, error) {
	return h.listScopedUpstreams(ctx, domain.AuthorizationScope{})
}
func (h *ScopedResourceHandler) listOrganizationUpstreams(ctx context.Context, input *organizationPathInput) (*upstreamListOutput, error) {
	return h.listScopedUpstreams(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID})
}
func (h *ScopedResourceHandler) listTeamUpstreams(ctx context.Context, input *teamPathInput) (*upstreamListOutput, error) {
	return h.listScopedUpstreams(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID, TeamID: input.TeamID})
}
func (h *ScopedResourceHandler) getAccountUpstream(ctx context.Context, input *accountUpstreamIDInput) (*upstreamOutput, error) {
	return h.getScopedUpstream(ctx, domain.AuthorizationScope{}, input.UpstreamID)
}
func (h *ScopedResourceHandler) getOrganizationUpstream(ctx context.Context, input *organizationUpstreamIDInput) (*upstreamOutput, error) {
	return h.getScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID}, input.UpstreamID)
}
func (h *ScopedResourceHandler) getTeamUpstream(ctx context.Context, input *teamUpstreamIDInput) (*upstreamOutput, error) {
	return h.getScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID, TeamID: input.TeamID}, input.UpstreamID)
}

type updateAccountUpstreamInput struct {
	UpstreamID string `path:"upstream_id" doc:"Upstream identifier"`
	Body       createUpstreamRequest
}
type updateOrganizationUpstreamInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	UpstreamID     string `path:"upstream_id" doc:"Upstream identifier"`
	Body           createUpstreamRequest
}
type updateTeamUpstreamInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	TeamID         string `path:"team_id" doc:"Team identifier"`
	UpstreamID     string `path:"upstream_id" doc:"Upstream identifier"`
	Body           createUpstreamRequest
}

func (h *ScopedResourceHandler) updateAccountUpstreamWithBody(ctx context.Context, input *updateAccountUpstreamInput) (*upstreamOutput, error) {
	return h.updateScopedUpstream(ctx, domain.AuthorizationScope{}, input.UpstreamID, input.Body)
}

func (h *ScopedResourceHandler) updateOrganizationUpstreamWithBody(ctx context.Context, input *updateOrganizationUpstreamInput) (*upstreamOutput, error) {
	return h.updateScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID}, input.UpstreamID, input.Body)
}

func (h *ScopedResourceHandler) updateTeamUpstreamWithBody(ctx context.Context, input *updateTeamUpstreamInput) (*upstreamOutput, error) {
	return h.updateScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID, TeamID: input.TeamID}, input.UpstreamID, input.Body)
}

func (h *ScopedResourceHandler) deleteAccountUpstream(ctx context.Context, input *accountUpstreamIDInput) (*struct{}, error) {
	return h.deleteScopedUpstream(ctx, domain.AuthorizationScope{}, input.UpstreamID)
}
func (h *ScopedResourceHandler) deleteOrganizationUpstream(ctx context.Context, input *organizationUpstreamIDInput) (*struct{}, error) {
	return h.deleteScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID}, input.UpstreamID)
}
func (h *ScopedResourceHandler) deleteTeamUpstream(ctx context.Context, input *teamUpstreamIDInput) (*struct{}, error) {
	return h.deleteScopedUpstream(ctx, domain.AuthorizationScope{OrganizationID: input.OrganizationID, TeamID: input.TeamID}, input.UpstreamID)
}

func (h *ScopedResourceHandler) createScopedUpstream(ctx context.Context, scope domain.AuthorizationScope, req createUpstreamRequest) (*upstreamOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	scope.TenantID = principal.TenantID
	upstream, err := upstreamFromScopedRequest(req)
	if err != nil {
		return nil, err
	}
	if err := h.upstreams.Create(ctx, principal, scope, upstream); err != nil {
		return nil, h.scopedError(ctx, "creating scoped upstream", err)
	}
	return &upstreamOutput{Body: toUpstreamResponse(upstream)}, nil
}

func (h *ScopedResourceHandler) listScopedUpstreams(ctx context.Context, scope domain.AuthorizationScope) (*upstreamListOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	scope.TenantID = principal.TenantID
	upstreams, err := h.upstreams.List(ctx, principal, scope)
	if err != nil {
		return nil, h.scopedError(ctx, "listing scoped upstreams", err)
	}
	return &upstreamListOutput{Body: toUpstreamsResponse(upstreams)}, nil
}

func (h *ScopedResourceHandler) getScopedUpstream(ctx context.Context, scope domain.AuthorizationScope, id string) (*upstreamOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	scope.TenantID = principal.TenantID
	upstream, err := h.upstreams.Get(ctx, principal, scope, id)
	if err != nil {
		return nil, h.scopedError(ctx, "getting scoped upstream", err)
	}
	return &upstreamOutput{Body: toUpstreamResponse(upstream)}, nil
}

func (h *ScopedResourceHandler) updateScopedUpstream(ctx context.Context, scope domain.AuthorizationScope, id string, req createUpstreamRequest) (*upstreamOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	scope.TenantID = principal.TenantID
	upstream, err := upstreamFromScopedRequest(req)
	if err != nil {
		return nil, err
	}
	upstream.ID = id
	if err := h.upstreams.Update(ctx, principal, scope, upstream); err != nil {
		return nil, h.scopedError(ctx, "updating scoped upstream", err)
	}
	updated, err := h.upstreams.Get(ctx, principal, scope, id)
	if err != nil {
		return nil, h.scopedError(ctx, "loading updated scoped upstream", err)
	}
	return &upstreamOutput{Body: toUpstreamResponse(updated)}, nil
}

func (h *ScopedResourceHandler) deleteScopedUpstream(ctx context.Context, scope domain.AuthorizationScope, id string) (*struct{}, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	scope.TenantID = principal.TenantID
	if err := h.upstreams.Delete(ctx, principal, scope, id); err != nil {
		return nil, h.scopedError(ctx, "deleting scoped upstream", err)
	}
	return nil, nil
}

func upstreamFromScopedRequest(req createUpstreamRequest) (*domain.Upstream, error) {
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	auth, err := toDomainUpstreamAuth(req.Ecosystem, req.Auth)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	return &domain.Upstream{Name: req.Name, Ecosystem: req.Ecosystem, BaseURL: req.BaseURL, Capabilities: req.Capabilities, Auth: auth}, nil
}

func (h *ScopedResourceHandler) scopedError(ctx context.Context, operation string, err error) error {
	if errors.Is(err, domain.ErrPolicyNotFound) || errors.Is(err, domain.ErrUpstreamNotFound) || errors.Is(err, domain.ErrOrganizationNotFound) || errors.Is(err, domain.ErrTeamNotFound) {
		return huma.Error404NotFound("resource not found")
	}
	var denial *domain.AuthorizationError
	if errors.As(err, &denial) {
		switch denial.Reason {
		case domain.AuthorizationDenialTenantMismatch, domain.AuthorizationDenialOrganizationNotFound, domain.AuthorizationDenialTeamNotFound:
			return huma.Error404NotFound("resource not found")
		default:
			return huma.Error403Forbidden("insufficient permission for this scope")
		}
	}
	if errors.Is(err, domain.ErrPolicyNameConflict) || errors.Is(err, domain.ErrUpstreamNameConflict) || errors.Is(err, domain.ErrUpstreamRegistryConflict) {
		return huma.Error409Conflict("name or registry already exists in this scope")
	}
	if errors.Is(err, domain.ErrPolicyDeleteEnabled) || errors.Is(err, domain.ErrPolicyInUse) || errors.Is(err, domain.ErrUpstreamInUse) {
		return huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, domain.ErrInvalidPolicy) || errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) || errors.Is(err, domain.ErrPolicyUpstreamIncompatible) || errors.Is(err, domain.ErrInvalidResourceScope) || errors.Is(err, domain.ErrUnsupportedUpstreamCapability) || errors.Is(err, domain.ErrUpstreamPolicyConflict) || errors.Is(err, domain.ErrUpstreamAuthInvalid) || errors.Is(err, domain.ErrUpstreamAuthKeyUnavailable) || errors.Is(err, domain.ErrUpstreamAuthTransportInsecure) {
		return huma.Error400BadRequest(err.Error())
	}
	return humaInternalError(ctx, h.logger, operation, err, "scoped resource operation failed")
}
