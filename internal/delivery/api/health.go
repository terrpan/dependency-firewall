package api

import (
	"log/slog"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// HealthHandler handles the health check endpoint.
type HealthHandler struct {
	healthService *service.HealthService
	logger        *slog.Logger
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(healthService *service.HealthService, logger *slog.Logger) *HealthHandler {
	return &HealthHandler{healthService: healthService, logger: logger}
}

// RegisterRoutes registers health check routes on the given mux.
func (h *HealthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.handleHealthCheck)
}

func (h *HealthHandler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	resp := h.healthService.CheckHealth(r.Context())

	status := http.StatusOK
	if resp.Status != "healthy" {
		status = http.StatusServiceUnavailable
	}

	writeJSON(w, status, resp)
}
