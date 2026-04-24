package api

import (
	"log/slog"
	"net/http"

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
	mux.HandleFunc("DELETE /api/v1/cache/decisions", h.clearDecisionCache)
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
