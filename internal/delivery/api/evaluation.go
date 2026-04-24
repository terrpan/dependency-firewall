package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// EvaluationHandler handles evaluation listing endpoints.
type EvaluationHandler struct {
	evaluations *service.EvaluationService
	logger      *slog.Logger
}

// NewEvaluationHandler creates a new EvaluationHandler.
func NewEvaluationHandler(evaluations *service.EvaluationService, logger *slog.Logger) *EvaluationHandler {
	return &EvaluationHandler{evaluations: evaluations, logger: logger}
}

// RegisterRoutes registers evaluation API routes on the given mux.
func (h *EvaluationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/evaluations", h.list)
}

func (h *EvaluationHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	decisions, err := h.evaluations.ListByTenant(r.Context(), tenantID, limit, offset)
	if err != nil {
		h.logger.Error("listing evaluations", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list evaluations")
		return
	}
	writeJSON(w, http.StatusOK, toDecisionsResponse(decisions))
}
