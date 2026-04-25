package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// UpstreamHandler handles upstream registry CRUD endpoints.
type UpstreamHandler struct {
	upstreams *service.UpstreamService
	logger    *slog.Logger
}

// NewUpstreamHandler creates a new UpstreamHandler.
func NewUpstreamHandler(upstreams *service.UpstreamService, logger *slog.Logger) *UpstreamHandler {
	return &UpstreamHandler{upstreams: upstreams, logger: logger}
}

// RegisterHumaRoutes registers upstream API routes on the control-plane Huma API.
func (h *UpstreamHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-upstream",
		Method:        http.MethodPost,
		Path:          "/api/v1/upstreams",
		Summary:       "Create an upstream",
		Description:   "Creates a tenant-scoped upstream registry configuration for npm or OCI proxying.",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"upstreams"},
		Errors:        []int{http.StatusBadRequest, http.StatusConflict, http.StatusInternalServerError},
	}, h.create)
	huma.Register(api, huma.Operation{
		OperationID: "list-upstreams",
		Method:      http.MethodGet,
		Path:        "/api/v1/upstreams",
		Summary:     "List upstreams",
		Description: "Lists the upstream registry configurations registered for the tenant.",
		Tags:        []string{"upstreams"},
		Errors:      []int{http.StatusBadRequest, http.StatusInternalServerError},
	}, h.list)
	huma.Register(api, huma.Operation{
		OperationID: "get-upstream",
		Method:      http.MethodGet,
		Path:        "/api/v1/upstreams/{id}",
		Summary:     "Get an upstream by ID",
		Description: "Returns one tenant-scoped upstream registry configuration by ID.",
		Tags:        []string{"upstreams"},
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError},
	}, h.get)
	huma.Register(api, huma.Operation{
		OperationID: "update-upstream",
		Method:      http.MethodPut,
		Path:        "/api/v1/upstreams/{id}",
		Summary:     "Update an upstream",
		Description: "Updates a tenant-scoped upstream registry configuration.",
		Tags:        []string{"upstreams"},
		Errors:      []int{http.StatusBadRequest, http.StatusConflict, http.StatusNotFound, http.StatusInternalServerError},
	}, h.update)
	huma.Register(api, huma.Operation{
		OperationID:   "delete-upstream",
		Method:        http.MethodDelete,
		Path:          "/api/v1/upstreams/{id}",
		Summary:       "Delete an upstream",
		Description:   "Deletes a tenant-scoped upstream registry configuration by ID.",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"upstreams"},
		Errors:        []int{http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError},
	}, h.delete)
	removeValidationResponse(api, "/api/v1/upstreams", http.MethodGet, http.MethodPost)
	removeValidationResponse(api, "/api/v1/upstreams/{id}", http.MethodGet, http.MethodPut, http.MethodDelete)
}

type createUpstreamRequest struct {
	Name      string               `json:"name,omitempty" validate:"notblank" doc:"Upstream display name"`
	Ecosystem domain.EcosystemType `json:"ecosystem,omitempty" validate:"required,oneof=npm oci" doc:"Upstream ecosystem"`
	BaseURL   string               `json:"base_url,omitempty" validate:"notblank,url" doc:"Upstream base URL"`
}

type upstreamHeaderInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
}

type createUpstreamInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	Body     createUpstreamRequest
}

type upstreamIDInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `path:"id" doc:"Upstream identifier"`
}

type updateUpstreamInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `path:"id" doc:"Upstream identifier"`
	Body     createUpstreamRequest
}

type upstreamOutput struct {
	Body *UpstreamResponse
}

type upstreamListOutput struct {
	Body []*UpstreamResponse
}

func (h *UpstreamHandler) create(ctx context.Context, input *createUpstreamInput) (*upstreamOutput, error) {
	resp, err := h.createUpstream(ctx, input.TenantID, input.Body)
	if err != nil {
		return nil, err
	}
	return &upstreamOutput{Body: resp}, nil
}

func (h *UpstreamHandler) list(ctx context.Context, input *upstreamHeaderInput) (*upstreamListOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	upstreams, err := h.upstreams.ListByTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("listing upstreams", "error", err)
		return nil, huma.Error500InternalServerError("failed to list upstreams")
	}
	return &upstreamListOutput{Body: toUpstreamsResponse(upstreams)}, nil
}

func (h *UpstreamHandler) get(ctx context.Context, input *upstreamIDInput) (*upstreamOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	upstream, err := h.upstreams.GetByID(ctx, tenantID, input.ID)
	if err != nil {
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			return nil, huma.Error404NotFound("upstream not found")
		}
		h.logger.Error("getting upstream", "error", err)
		return nil, huma.Error500InternalServerError("failed to get upstream")
	}
	return &upstreamOutput{Body: toUpstreamResponse(upstream)}, nil
}

func (h *UpstreamHandler) update(ctx context.Context, input *updateUpstreamInput) (*upstreamOutput, error) {
	resp, err := h.updateUpstream(ctx, input.TenantID, input.ID, input.Body)
	if err != nil {
		return nil, err
	}
	return &upstreamOutput{Body: resp}, nil
}

func (h *UpstreamHandler) delete(ctx context.Context, input *upstreamIDInput) (*struct{}, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	if err := h.upstreams.Delete(ctx, tenantID, input.ID); err != nil {
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			return nil, huma.Error404NotFound("upstream not found")
		}
		h.logger.Error("deleting upstream", "error", err)
		return nil, huma.Error500InternalServerError("failed to delete upstream")
	}
	return nil, nil
}

func (h *UpstreamHandler) createUpstream(ctx context.Context, rawTenantID string, req createUpstreamRequest) (*UpstreamResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	upstream := &domain.Upstream{
		TenantID:  tenantID,
		Name:      req.Name,
		Ecosystem: req.Ecosystem,
		BaseURL:   req.BaseURL,
	}
	if err := h.upstreams.Create(ctx, upstream); err != nil {
		if errors.Is(err, domain.ErrUpstreamNameConflict) {
			return nil, huma.Error409Conflict("upstream name already exists")
		}
		if errors.Is(err, domain.ErrUpstreamScopeConflict) {
			return nil, huma.Error409Conflict("upstream for ecosystem already exists")
		}
		h.logger.Error("creating upstream", "error", err)
		return nil, huma.Error500InternalServerError("failed to create upstream")
	}
	return toUpstreamResponse(upstream), nil
}

func (h *UpstreamHandler) updateUpstream(ctx context.Context, rawTenantID, id string, req createUpstreamRequest) (*UpstreamResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	upstream := &domain.Upstream{
		ID:        id,
		TenantID:  tenantID,
		Name:      req.Name,
		Ecosystem: req.Ecosystem,
		BaseURL:   req.BaseURL,
	}
	if err := h.upstreams.Update(ctx, upstream); err != nil {
		if errors.Is(err, domain.ErrUpstreamNameConflict) {
			return nil, huma.Error409Conflict("upstream name already exists")
		}
		if errors.Is(err, domain.ErrUpstreamScopeConflict) {
			return nil, huma.Error409Conflict("upstream for ecosystem already exists")
		}
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			return nil, huma.Error404NotFound("upstream not found")
		}
		h.logger.Error("updating upstream", "error", err)
		return nil, huma.Error500InternalServerError("failed to update upstream")
	}
	return toUpstreamResponse(upstream), nil
}
