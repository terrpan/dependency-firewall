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
		Errors:      []int{http.StatusBadRequest, http.StatusInternalServerError},
	}, h.clearDecisionCacheHuma)
	removeValidationResponse(api, "/api/v1/cache/decisions", http.MethodDelete)
}

type cacheTenantInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
}

type cacheClearOutput struct {
	Body cacheClearResponse
}

func (h *CacheHandler) clearDecisionCache(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.caches.ClearTenantDecisions(r.Context(), tenantID); err != nil {
		h.logger.Error("clearing tenant decision cache", "error", err, "tenant_id", tenantID)
		writeError(w, http.StatusInternalServerError, "failed to clear decision cache")
		return
	}

	writeJSON(w, http.StatusOK, cacheClearResponse{
		Status: "cleared",
		Cache:  "decisions",
	})
}

func (h *CacheHandler) clearDecisionCacheHuma(ctx context.Context, input *cacheTenantInput) (*cacheClearOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	if err := h.caches.ClearTenantDecisions(ctx, tenantID); err != nil {
		h.logger.Error("clearing tenant decision cache", "error", err, "tenant_id", tenantID)
		return nil, huma.Error500InternalServerError("failed to clear decision cache")
	}

	return &cacheClearOutput{
		Body: cacheClearResponse{
			Status: "cleared",
			Cache:  "decisions",
		},
	}, nil
}
