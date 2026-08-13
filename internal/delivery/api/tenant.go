package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

// TenantHandler handles tenant CRUD endpoints.
type TenantHandler struct {
	tenants *service.TenantService
	logger  *slog.Logger
}

// NewTenantHandler creates a new TenantHandler.
func NewTenantHandler(tenants *service.TenantService, logger *slog.Logger) *TenantHandler {
	return &TenantHandler{tenants: tenants, logger: logger}
}

// RegisterHumaRoutes registers tenant API routes on the control-plane Huma API.
func (h *TenantHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-tenant",
		Method:        http.MethodPost,
		Path:          "/api/v1/tenants",
		Summary:       "Create a tenant",
		Description:   "Creates a tenant record used to scope control-plane resources and proxy policy decisions.",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"tenants"},
		Errors:        controlPlaneErrors(http.StatusBadRequest, http.StatusConflict, http.StatusInternalServerError),
	}, h.create)
	huma.Register(api, huma.Operation{
		OperationID: "list-tenants",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants",
		Summary:     "List tenants",
		Description: "Lists all configured tenants managed by the control plane.",
		Tags:        []string{"tenants"},
		Errors:      controlPlaneReadErrors(http.StatusInternalServerError),
	}, h.list)
	huma.Register(api, huma.Operation{
		OperationID: "get-tenant",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{id}",
		Summary:     "Get a tenant by ID",
		Description: "Returns one tenant record by its identifier.",
		Tags:        []string{"tenants"},
		Errors:      controlPlaneReadErrors(http.StatusNotFound, http.StatusInternalServerError),
	}, h.get)
	huma.Register(api, huma.Operation{
		OperationID: "update-tenant",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{id}",
		Summary:     "Update a tenant",
		Description: "Updates the mutable fields of an existing tenant record.",
		Tags:        []string{"tenants"},
		Errors: controlPlaneErrors(
			http.StatusBadRequest,
			http.StatusConflict,
			http.StatusNotFound,
			http.StatusInternalServerError,
		),
	}, h.update)
	huma.Register(api, huma.Operation{
		OperationID:   "delete-tenant",
		Method:        http.MethodDelete,
		Path:          "/api/v1/tenants/{id}",
		Summary:       "Delete a tenant",
		Description:   "Deletes a tenant record by ID.",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"tenants"},
		Errors:        controlPlaneErrors(http.StatusNotFound, http.StatusInternalServerError),
	}, h.delete)
	removeValidationResponse(api, "/api/v1/tenants", http.MethodGet, http.MethodPost)
	removeValidationResponse(api, "/api/v1/tenants/{id}", http.MethodGet, http.MethodPut, http.MethodDelete)
}

type createTenantRequest struct {
	Name string `json:"name" validate:"notblank" doc:"Tenant display name"`
}

type createTenantInput struct {
	Body createTenantRequest
}

type tenantIDInput struct {
	ID string `path:"id" doc:"Tenant identifier"`
}

type updateTenantInput struct {
	ID   string `path:"id" doc:"Tenant identifier"`
	Body createTenantRequest
}

type tenantOutput struct {
	Body *TenantResponse
}

type tenantListOutput struct {
	Body []*TenantResponse
}

func (h *TenantHandler) create(ctx context.Context, input *createTenantInput) (*tenantOutput, error) {
	if _, authenticated := middleware.AuthenticatedPrincipalFromContext(ctx); authenticated {
		return nil, huma.Error403Forbidden("accounts are provisioned through session bootstrap")
	}
	resp, err := h.createTenant(ctx, input.Body)
	if err != nil {
		return nil, err
	}
	return &tenantOutput{Body: resp}, nil
}

func (h *TenantHandler) list(ctx context.Context, _ *struct{}) (*tenantListOutput, error) {
	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()

	if principal, authenticated := middleware.AuthenticatedPrincipalFromContext(ctx); authenticated {
		tenant, err := h.tenants.GetByID(ctx, principal.TenantID)
		if err != nil {
			return nil, humaInternalError(ctx, h.logger, "listing active account", err, "failed to list account")
		}
		return &tenantListOutput{Body: toTenantsResponse([]domain.Tenant{*tenant})}, nil
	}
	tenants, err := h.tenants.List(ctx)
	if err != nil {
		return nil, humaInternalError(ctx, h.logger, "listing tenants", err, "failed to list tenants")
	}
	return &tenantListOutput{Body: toTenantsResponse(tenants)}, nil
}

func (h *TenantHandler) get(ctx context.Context, input *tenantIDInput) (*tenantOutput, error) {
	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()
	if principal, authenticated := middleware.AuthenticatedPrincipalFromContext(ctx); authenticated && input.ID != principal.TenantID {
		return nil, huma.Error404NotFound("tenant not found")
	}

	tenant, err := h.tenants.GetByID(ctx, input.ID)
	if err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) {
			return nil, huma.Error404NotFound("tenant not found")
		}
		return nil, humaInternalError(
			ctx,
			h.logger,
			"getting tenant",
			err,
			"failed to get tenant",
			"tenant_id",
			input.ID,
		)
	}
	return &tenantOutput{Body: toTenantResponse(tenant)}, nil
}

func (h *TenantHandler) update(ctx context.Context, input *updateTenantInput) (*tenantOutput, error) {
	if principal, authenticated := middleware.AuthenticatedPrincipalFromContext(ctx); authenticated && input.ID != principal.TenantID {
		return nil, huma.Error404NotFound("tenant not found")
	}
	resp, err := h.updateTenant(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}
	return &tenantOutput{Body: resp}, nil
}

func (h *TenantHandler) delete(ctx context.Context, input *tenantIDInput) (*struct{}, error) {
	if _, authenticated := middleware.AuthenticatedPrincipalFromContext(ctx); authenticated {
		return nil, huma.Error403Forbidden("self-service account deletion is disabled")
	}
	if err := h.tenants.Delete(ctx, input.ID); err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) {
			return nil, huma.Error404NotFound("tenant not found")
		}
		return nil, humaInternalError(
			ctx,
			h.logger,
			"deleting tenant",
			err,
			"failed to delete tenant",
			"tenant_id",
			input.ID,
		)
	}
	return nil, nil
}

func (h *TenantHandler) createTenant(ctx context.Context, req createTenantRequest) (*TenantResponse, error) {
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	tenant := &domain.Tenant{Name: req.Name}
	if err := h.tenants.Create(ctx, tenant); err != nil {
		if errors.Is(err, domain.ErrTenantNameConflict) {
			return nil, huma.Error409Conflict("tenant name already exists")
		}
		return nil, humaInternalError(
			ctx,
			h.logger,
			"creating tenant",
			err,
			"failed to create tenant",
			"tenant_name",
			req.Name,
		)
	}
	return toTenantResponse(tenant), nil
}

func (h *TenantHandler) updateTenant(ctx context.Context, id string, req createTenantRequest) (*TenantResponse, error) {
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	tenant := &domain.Tenant{ID: id, Name: req.Name}
	if err := h.tenants.Update(ctx, tenant); err != nil {
		if errors.Is(err, domain.ErrTenantNameConflict) {
			return nil, huma.Error409Conflict("tenant name already exists")
		}
		if errors.Is(err, domain.ErrTenantNotFound) {
			return nil, huma.Error404NotFound("tenant not found")
		}
		return nil, humaInternalError(ctx, h.logger, "updating tenant", err, "failed to update tenant", "tenant_id", id)
	}
	return toTenantResponse(tenant), nil
}
