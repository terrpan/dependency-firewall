package api

import (
	"log/slog"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// HealthHandler handles the health check endpoint.
type HealthHandler struct {
	healthService *service.HealthService
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(healthService *service.HealthService, logger *slog.Logger) *HealthHandler {
	_ = logger
	return &HealthHandler{healthService: healthService}
}

// RegisterRoutes registers health check routes on the given mux.
func (h *HealthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.handleHealthCheck)
}

func (h *HealthHandler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	status := h.healthService.CheckHealth(r.Context())

	httpStatus := http.StatusOK
	if status.Status != "healthy" {
		httpStatus = http.StatusServiceUnavailable
	}

	writeJSON(w, httpStatus, toHealthResponse(status))
}
