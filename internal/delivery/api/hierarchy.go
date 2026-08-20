package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

// HierarchyHandler models a hierarchy handler.
type HierarchyHandler struct {
	hierarchy *service.HierarchyService
	logger    *slog.Logger
}

// NewHierarchyHandler constructs a new HierarchyHandler.
func NewHierarchyHandler(hierarchy *service.HierarchyService, logger *slog.Logger) *HierarchyHandler {
	return &HierarchyHandler{hierarchy: hierarchy, logger: logger}
}

// RegisterHumaRoutes registers the Organization and Team management endpoints.
func (h *HierarchyHandler) RegisterHumaRoutes(api huma.API) {
	h.registerOrganizationRoutes(api)
	h.registerTeamRoutes(api)
}

func (h *HierarchyHandler) registerOrganizationRoutes(api huma.API) {
	huma.Register(
		api,
		huma.Operation{
			OperationID: "list-organizations",
			Method:      http.MethodGet,
			Path:        "/api/v1/organizations",
			Summary:     "List assigned Organizations",
			Tags:        []string{"organizations"},
			Errors:      hierarchyErrors(),
		},
		h.listOrganizations,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID:   "create-organization",
			Method:        http.MethodPost,
			Path:          "/api/v1/organizations",
			Summary:       "Create an Organization",
			DefaultStatus: http.StatusCreated,
			Tags:          []string{"organizations"},
			Errors:        hierarchyErrors(),
		},
		h.createOrganization,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID: "get-organization",
			Method:      http.MethodGet,
			Path:        "/api/v1/organizations/{organization_id}",
			Summary:     "Get an Organization",
			Tags:        []string{"organizations"},
			Errors:      hierarchyErrors(),
		},
		h.getOrganization,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID: "update-organization",
			Method:      http.MethodPatch,
			Path:        "/api/v1/organizations/{organization_id}",
			Summary:     "Update an Organization",
			Tags:        []string{"organizations"},
			Errors:      hierarchyErrors(),
		},
		h.updateOrganization,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID: "get-organization-member",
			Method:      http.MethodGet,
			Path:        "/api/v1/organizations/{organization_id}/members/{principal_id}",
			Summary:     "Get an Organization role assignment",
			Tags:        []string{"organization-members"},
			Errors:      hierarchyErrors(),
		},
		h.getOrganizationMember,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID: "set-organization-member",
			Method:      http.MethodPut,
			Path:        "/api/v1/organizations/{organization_id}/members/{principal_id}",
			Summary:     "Set an Organization role assignment",
			Tags:        []string{"organization-members"},
			Errors:      hierarchyErrors(),
		},
		h.setOrganizationMember,
	)
}

func (h *HierarchyHandler) registerTeamRoutes(api huma.API) {
	h.registerTeamResourceRoutes(api)
	h.registerTeamMemberRoutes(api)
}

func (h *HierarchyHandler) registerTeamResourceRoutes(api huma.API) {
	huma.Register(
		api,
		huma.Operation{
			OperationID: "list-teams",
			Method:      http.MethodGet,
			Path:        "/api/v1/organizations/{organization_id}/teams",
			Summary:     "List accessible Teams",
			Tags:        []string{"teams"},
			Errors:      hierarchyErrors(),
		},
		h.listTeams,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID:   "create-team",
			Method:        http.MethodPost,
			Path:          "/api/v1/organizations/{organization_id}/teams",
			Summary:       "Create a Team",
			DefaultStatus: http.StatusCreated,
			Tags:          []string{"teams"},
			Errors:        hierarchyErrors(),
		},
		h.createTeam,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID: "get-team",
			Method:      http.MethodGet,
			Path:        "/api/v1/organizations/{organization_id}/teams/{team_id}",
			Summary:     "Get a Team",
			Tags:        []string{"teams"},
			Errors:      hierarchyErrors(),
		},
		h.getTeam,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID: "update-team",
			Method:      http.MethodPatch,
			Path:        "/api/v1/organizations/{organization_id}/teams/{team_id}",
			Summary:     "Update or archive a Team",
			Tags:        []string{"teams"},
			Errors:      hierarchyErrors(),
		},
		h.updateTeam,
	)
}

func (h *HierarchyHandler) registerTeamMemberRoutes(api huma.API) {
	huma.Register(
		api,
		huma.Operation{
			OperationID: "get-team-member",
			Method:      http.MethodGet,
			Path:        "/api/v1/organizations/{organization_id}/teams/{team_id}/members/{principal_id}",
			Summary:     "Get a Team membership",
			Tags:        []string{"team-members"},
			Errors:      hierarchyErrors(),
		},
		h.getTeamMember,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID: "set-team-member",
			Method:      http.MethodPut,
			Path:        "/api/v1/organizations/{organization_id}/teams/{team_id}/members/{principal_id}",
			Summary:     "Add a Team member",
			Tags:        []string{"team-members"},
			Errors:      hierarchyErrors(),
		},
		h.setTeamMember,
	)
	huma.Register(
		api,
		huma.Operation{
			OperationID:   "delete-team-member",
			Method:        http.MethodDelete,
			Path:          "/api/v1/organizations/{organization_id}/teams/{team_id}/members/{principal_id}",
			Summary:       "Remove a Team member",
			DefaultStatus: http.StatusNoContent,
			Tags:          []string{"team-members"},
			Errors:        hierarchyErrors(),
		},
		h.deleteTeamMember,
	)
}

func hierarchyErrors() []int {
	return controlPlaneErrors(
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	)
}

type organizationPathInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
}

type organizationMemberPathInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	PrincipalID    string `path:"principal_id"    doc:"Principal identifier"`
}

type teamPathInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	TeamID         string `path:"team_id"         doc:"Team identifier"`
}

type teamMemberPathInput struct {
	OrganizationID string `path:"organization_id" doc:"Organization identifier"`
	TeamID         string `path:"team_id"         doc:"Team identifier"`
	PrincipalID    string `path:"principal_id"    doc:"Principal identifier"`
}

type organizationRequest struct {
	Name string `json:"name" validate:"notblank"`
}

type updateOrganizationRequest struct {
	Name   string                    `json:"name"   validate:"notblank"`
	Status domain.OrganizationStatus `json:"status" validate:"required,oneof=active archived"`
}

type organizationInput struct{ Body organizationRequest }
type updateOrganizationInput struct {
	OrganizationID string `path:"organization_id"`
	Body           updateOrganizationRequest
}

type organizationMemberRequest struct {
	Role domain.OrganizationRole `json:"role" validate:"required,oneof=admin policy_manager operator viewer"`
}

type setOrganizationMemberInput struct {
	OrganizationID string `path:"organization_id"`
	PrincipalID    string `path:"principal_id"`
	Body           organizationMemberRequest
}

type teamRequest struct {
	Name string `json:"name" validate:"notblank"`
}

type createTeamInput struct {
	OrganizationID string `path:"organization_id"`
	Body           teamRequest
}

type updateTeamRequest struct {
	Name     string `json:"name"     validate:"notblank"`
	Archived bool   `json:"archived"`
}

type updateTeamInput struct {
	OrganizationID string `path:"organization_id"`
	TeamID         string `path:"team_id"`
	Body           updateTeamRequest
}

// OrganizationResponse models an organization response.
type OrganizationResponse struct {
	ID          string                    `json:"id"`
	TenantID    string                    `json:"tenant_id"`
	Name        string                    `json:"name"`
	Status      domain.OrganizationStatus `json:"status"`
	IsDefault   bool                      `json:"is_default"`
	Role        domain.OrganizationRole   `json:"role"`
	Permissions []domain.Permission       `json:"permissions"`
	Scope       string                    `json:"scope"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

// TeamResponse models a team response.
type TeamResponse struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	OrganizationID string     `json:"organization_id"`
	Name           string     `json:"name"`
	ArchivedAt     *time.Time `json:"archived_at,omitempty"`
	Scope          string     `json:"scope"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// OrganizationMembershipResponse models an organization membership response.
type OrganizationMembershipResponse struct {
	TenantID       string                  `json:"tenant_id"`
	OrganizationID string                  `json:"organization_id"`
	PrincipalID    string                  `json:"principal_id"`
	Role           domain.OrganizationRole `json:"role"`
	CreatedAt      time.Time               `json:"created_at"`
	UpdatedAt      time.Time               `json:"updated_at"`
}

// TeamMembershipResponse models a team membership response.
type TeamMembershipResponse struct {
	TenantID       string     `json:"tenant_id"`
	OrganizationID string     `json:"organization_id"`
	TeamID         string     `json:"team_id"`
	PrincipalID    string     `json:"principal_id"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
}

type organizationOutput struct{ Body *OrganizationResponse }
type organizationListOutput struct{ Body []*OrganizationResponse }
type organizationMembershipOutput struct {
	Body *OrganizationMembershipResponse
}
type teamOutput struct{ Body *TeamResponse }
type teamListOutput struct{ Body []*TeamResponse }
type teamMembershipOutput struct{ Body *TeamMembershipResponse }

func (h *HierarchyHandler) listOrganizations(ctx context.Context, _ *struct{}) (*organizationListOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	items, err := h.hierarchy.ListOrganizations(ctx, principal)
	if err != nil {
		return nil, h.hierarchyError(ctx, "listing organizations", err)
	}
	result := make([]*OrganizationResponse, 0, len(items))
	for _, item := range items {
		result = append(result, organizationResponse(item.Organization, item.Role))
	}
	return &organizationListOutput{Body: result}, nil
}

func (h *HierarchyHandler) createOrganization(
	ctx context.Context,
	input *organizationInput,
) (*organizationOutput, error) {
	if err := validateRequest(input.Body); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	organization, err := h.hierarchy.CreateOrganization(ctx, principal, input.Body.Name)
	if err != nil {
		return nil, h.hierarchyError(ctx, "creating organization", err)
	}
	return &organizationOutput{Body: organizationResponse(*organization, domain.OrganizationRoleAdmin)}, nil
}

func (h *HierarchyHandler) getOrganization(
	ctx context.Context,
	input *organizationPathInput,
) (*organizationOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	item, err := h.hierarchy.GetOrganization(ctx, principal, input.OrganizationID)
	if err != nil {
		return nil, h.hierarchyError(ctx, "getting organization", err)
	}
	return &organizationOutput{Body: organizationResponse(item.Organization, item.Role)}, nil
}

func (h *HierarchyHandler) updateOrganization(
	ctx context.Context,
	input *updateOrganizationInput,
) (*organizationOutput, error) {
	if err := validateRequest(input.Body); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	organization, err := h.hierarchy.UpdateOrganization(
		ctx,
		principal,
		input.OrganizationID,
		input.Body.Name,
		input.Body.Status,
	)
	if err != nil {
		return nil, h.hierarchyError(ctx, "updating organization", err)
	}
	return &organizationOutput{Body: organizationResponse(*organization, domain.OrganizationRoleAdmin)}, nil
}

func (h *HierarchyHandler) getOrganizationMember(
	ctx context.Context,
	input *organizationMemberPathInput,
) (*organizationMembershipOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	membership, err := h.hierarchy.GetOrganizationMembership(ctx, principal, input.OrganizationID, input.PrincipalID)
	if err != nil {
		return nil, h.hierarchyError(ctx, "getting organization member", err)
	}
	return &organizationMembershipOutput{Body: organizationMembershipResponse(membership)}, nil
}

func (h *HierarchyHandler) setOrganizationMember(
	ctx context.Context,
	input *setOrganizationMemberInput,
) (*organizationMembershipOutput, error) {
	if err := validateRequest(input.Body); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	membership, err := h.hierarchy.SetOrganizationMembership(
		ctx,
		principal,
		input.OrganizationID,
		input.PrincipalID,
		input.Body.Role,
	)
	if err != nil {
		return nil, h.hierarchyError(ctx, "setting organization member", err)
	}
	return &organizationMembershipOutput{Body: organizationMembershipResponse(membership)}, nil
}

func (h *HierarchyHandler) listTeams(ctx context.Context, input *organizationPathInput) (*teamListOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	items, err := h.hierarchy.ListTeams(ctx, principal, input.OrganizationID)
	if err != nil {
		return nil, h.hierarchyError(ctx, "listing teams", err)
	}
	result := make([]*TeamResponse, 0, len(items))
	for _, item := range items {
		result = append(result, teamResponse(item))
	}
	return &teamListOutput{Body: result}, nil
}

func (h *HierarchyHandler) createTeam(ctx context.Context, input *createTeamInput) (*teamOutput, error) {
	if err := validateRequest(input.Body); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	team, err := h.hierarchy.CreateTeam(ctx, principal, input.OrganizationID, input.Body.Name)
	if err != nil {
		return nil, h.hierarchyError(ctx, "creating team", err)
	}
	return &teamOutput{Body: teamResponse(*team)}, nil
}

func (h *HierarchyHandler) getTeam(ctx context.Context, input *teamPathInput) (*teamOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	team, err := h.hierarchy.GetTeam(ctx, principal, input.OrganizationID, input.TeamID)
	if err != nil {
		return nil, h.hierarchyError(ctx, "getting team", err)
	}
	return &teamOutput{Body: teamResponse(*team)}, nil
}

func (h *HierarchyHandler) updateTeam(ctx context.Context, input *updateTeamInput) (*teamOutput, error) {
	if err := validateRequest(input.Body); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	team, err := h.hierarchy.UpdateTeam(
		ctx,
		principal,
		input.OrganizationID,
		input.TeamID,
		input.Body.Name,
		input.Body.Archived,
	)
	if err != nil {
		return nil, h.hierarchyError(ctx, "updating team", err)
	}
	return &teamOutput{Body: teamResponse(*team)}, nil
}

func (h *HierarchyHandler) getTeamMember(
	ctx context.Context,
	input *teamMemberPathInput,
) (*teamMembershipOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	member, err := h.hierarchy.IsTeamMember(ctx, principal, input.OrganizationID, input.TeamID, input.PrincipalID)
	if err != nil {
		return nil, h.hierarchyError(ctx, "getting team member", err)
	}
	if !member {
		return nil, huma.Error404NotFound("team membership not found")
	}
	return &teamMembershipOutput{
		Body: &TeamMembershipResponse{
			TenantID:       principal.TenantID,
			OrganizationID: input.OrganizationID,
			TeamID:         input.TeamID,
			PrincipalID:    input.PrincipalID,
		},
	}, nil
}

func (h *HierarchyHandler) setTeamMember(
	ctx context.Context,
	input *teamMemberPathInput,
) (*teamMembershipOutput, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	membership, err := h.hierarchy.SetTeamMembership(
		ctx,
		principal,
		input.OrganizationID,
		input.TeamID,
		input.PrincipalID,
	)
	if err != nil {
		return nil, h.hierarchyError(ctx, "setting team member", err)
	}
	return &teamMembershipOutput{Body: teamMembershipResponse(membership)}, nil
}

func (h *HierarchyHandler) deleteTeamMember(ctx context.Context, input *teamMemberPathInput) (*struct{}, error) {
	principal, err := hierarchyPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.hierarchy.DeleteTeamMembership(
		ctx,
		principal,
		input.OrganizationID,
		input.TeamID,
		input.PrincipalID,
	); err != nil {
		return nil, h.hierarchyError(ctx, "deleting team member", err)
	}
	return nil, nil
}

func hierarchyPrincipal(ctx context.Context) (domain.AuthenticatedPrincipal, error) {
	principal, ok := middleware.AuthenticatedPrincipalFromContext(ctx)
	if !ok {
		return domain.AuthenticatedPrincipal{}, huma.Error401Unauthorized("authenticated session required")
	}
	return principal, nil
}

func (h *HierarchyHandler) hierarchyError(ctx context.Context, operation string, err error) error {
	if errors.Is(err, domain.ErrOrganizationNotFound) || errors.Is(err, domain.ErrTeamNotFound) ||
		errors.Is(err, domain.ErrPrincipalNotFound) ||
		errors.Is(err, domain.ErrOrganizationMembershipNotFound) ||
		errors.Is(err, domain.ErrTeamMembershipNotFound) {
		return huma.Error404NotFound("resource not found")
	}
	if errors.Is(err, domain.ErrOrganizationNameConflict) || errors.Is(err, domain.ErrTeamNameConflict) {
		return huma.Error409Conflict("name already exists in this scope")
	}
	if errors.Is(err, domain.ErrUnauthorized) {
		return huma.Error403Forbidden("access denied")
	}
	if errors.Is(err, domain.ErrMembershipCheckUnavailable) {
		return huma.Error503ServiceUnavailable("tenant membership verification unavailable")
	}
	var denial *domain.AuthorizationError
	if errors.As(err, &denial) {
		if denial.Reason == domain.AuthorizationDenialOrganizationNotFound ||
			denial.Reason == domain.AuthorizationDenialTeamNotFound ||
			denial.Reason == domain.AuthorizationDenialTenantMismatch {
			return huma.Error404NotFound("resource not found")
		}
		return huma.Error403Forbidden("insufficient permission for this scope")
	}
	return humaInternalError(ctx, h.logger, operation, err, "hierarchy operation failed")
}

func organizationResponse(organization domain.Organization, role domain.OrganizationRole) *OrganizationResponse {
	return &OrganizationResponse{
		ID:          organization.ID,
		TenantID:    organization.TenantID,
		Name:        organization.Name,
		Status:      organization.Status,
		IsDefault:   organization.IsDefault,
		Role:        role,
		Permissions: service.PermissionsForOrganizationRole(role),
		Scope:       "organization",
		CreatedAt:   organization.CreatedAt,
		UpdatedAt:   organization.UpdatedAt,
	}
}

func teamResponse(team domain.Team) *TeamResponse {
	return &TeamResponse{
		ID:             team.ID,
		TenantID:       team.TenantID,
		OrganizationID: team.OrganizationID,
		Name:           team.Name,
		ArchivedAt:     team.ArchivedAt,
		Scope:          "team",
		CreatedAt:      team.CreatedAt,
		UpdatedAt:      team.UpdatedAt,
	}
}

func organizationMembershipResponse(membership *domain.OrganizationMembership) *OrganizationMembershipResponse {
	return &OrganizationMembershipResponse{
		TenantID:       membership.TenantID,
		OrganizationID: membership.OrganizationID,
		PrincipalID:    membership.PrincipalID,
		Role:           membership.Role,
		CreatedAt:      membership.CreatedAt,
		UpdatedAt:      membership.UpdatedAt,
	}
}

func teamMembershipResponse(membership *domain.TeamMembership) *TeamMembershipResponse {
	response := &TeamMembershipResponse{
		TenantID:       membership.TenantID,
		OrganizationID: membership.OrganizationID,
		TeamID:         membership.TeamID,
		PrincipalID:    membership.PrincipalID,
	}
	if !membership.CreatedAt.IsZero() {
		response.CreatedAt = &membership.CreatedAt
	}
	return response
}
