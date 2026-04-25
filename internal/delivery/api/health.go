package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

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

type healthOutput struct {
	Status int
	Body   healthResponse
}

// RegisterHumaRoutes registers health check routes on the control-plane Huma API.
func (h *HealthHandler) RegisterHumaRoutes(api huma.API) {
	huma.Get(api, "/healthz", h.handleHealthCheck,
		huma.OperationTags("health"),
		func(o *huma.Operation) {
			o.OperationID = "get-health"
			o.Summary = "Get service health"
			o.Description = "Returns process health for control-plane readiness checks. Responds with 503 when the service is unhealthy."
		},
	)
	removeValidationResponse(api, "/healthz", http.MethodGet)
}

func (h *HealthHandler) handleHealthCheck(ctx context.Context, _ *struct{}) (*healthOutput, error) {
	status := h.healthService.CheckHealth(ctx)

	httpStatus := http.StatusOK
	if status.Status != "healthy" {
		httpStatus = http.StatusServiceUnavailable
	}

	return &healthOutput{
		Status: httpStatus,
		Body:   toHealthResponse(status),
	}, nil
}
