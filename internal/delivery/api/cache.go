package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// CacheHandler handles cache maintenance endpoints.
type CacheHandler struct {
	caches *service.CacheService
	logger *slog.Logger
}

// NewCacheHandler creates a new CacheHandler.
func NewCacheHandler(caches *service.CacheService, logger *slog.Logger) *CacheHandler {
	return &CacheHandler{caches: caches, logger: logger}
}

// RegisterRoutes registers cache API routes on the given mux.
func (h *CacheHandler) RegisterRoutes(mux *http.ServeMux) {
}

// RegisterHumaRoutes registers cache maintenance routes on the control-plane Huma API.
func (h *CacheHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "clear-decision-cache",
		Method:      http.MethodDelete,
		Path:        "/api/v1/cache/decisions",
		Summary:     "Clear tenant decision cache",
		Description: "Invalidates cached policy decisions for the tenant so subsequent proxy requests are evaluated again.",
		Tags:        []string{"cache"},
		Errors:      controlPlaneErrors(http.StatusBadRequest, http.StatusInternalServerError),
	}, h.clearDecisionCacheHuma)
	removeValidationResponse(api, "/api/v1/cache/decisions", http.MethodDelete)

	huma.Register(api, huma.Operation{
		OperationID: "clear-metadata-cache",
		Method:      http.MethodDelete,
		Path:        "/api/v1/cache/metadata",
		Summary:     "Clear tenant metadata cache",
		Description: "Invalidates cached enrichment metadata for the tenant so subsequent proxy requests fetch fresh artifact metadata again.",
		Tags:        []string{"cache"},
		Errors:      controlPlaneErrors(http.StatusBadRequest, http.StatusInternalServerError),
	}, h.clearMetadataCacheHuma)
	removeValidationResponse(api, "/api/v1/cache/metadata", http.MethodDelete)
}

type cacheTenantInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
}

type cacheClearOutput struct {
	Body cacheClearResponse
}

func (h *CacheHandler) clearDecisionCacheHuma(ctx context.Context, input *cacheTenantInput) (*cacheClearOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	if err := h.caches.ClearTenantDecisions(ctx, tenantID); err != nil {
		return nil, humaInternalError(ctx, h.logger, "clearing tenant decision cache", err, "failed to clear decision cache", "tenant_id", tenantID)
	}

	return &cacheClearOutput{
		Body: cacheClearResponse{
			Status: "cleared",
			Cache:  "decisions",
		},
	}, nil
}

func (h *CacheHandler) clearMetadataCacheHuma(ctx context.Context, input *cacheTenantInput) (*cacheClearOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	if err := h.caches.ClearTenantMetadata(ctx, tenantID); err != nil {
		return nil, humaInternalError(ctx, h.logger, "clearing tenant metadata cache", err, "failed to clear metadata cache", "tenant_id", tenantID)
	}

	return &cacheClearOutput{
		Body: cacheClearResponse{
			Status: "cleared",
			Cache:  "metadata",
		},
	}, nil
}
