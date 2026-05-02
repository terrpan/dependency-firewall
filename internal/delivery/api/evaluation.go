package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

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
}

// RegisterHumaRoutes registers evaluation routes on the control-plane Huma API.
func (h *EvaluationHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-evaluations",
		Method:      http.MethodGet,
		Path:        "/api/v1/evaluations",
		Summary:     "List evaluations",
		Description: "Lists recorded evaluation decisions for the tenant. Supports limit and offset query parameters for pagination.",
		Tags:        []string{"evaluations"},
		Errors:      []int{http.StatusBadRequest, http.StatusInternalServerError},
	}, h.listHuma)
	removeValidationResponse(api, "/api/v1/evaluations", http.MethodGet)
}

type evaluationListInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	Limit    string `query:"limit" doc:"Maximum evaluations to return"`
	Offset   string `query:"offset" doc:"Evaluations to skip"`
	Search   string `query:"search" doc:"Case-insensitive artifact search across namespace, name, version, and digest"`
}

type evaluationListOutput struct {
	Body []*DecisionResponse
}

func (h *EvaluationHandler) listHuma(ctx context.Context, input *evaluationListInput) (*evaluationListOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	limit, offset := parseEvaluationPagination(input.Limit, input.Offset)
	decisions, err := h.evaluations.ListByTenant(ctx, tenantID, limit, offset, strings.TrimSpace(input.Search))
	if err != nil {
		h.logger.Error("listing evaluations", "error", err)
		return nil, huma.Error500InternalServerError("failed to list evaluations")
	}

	return &evaluationListOutput{Body: toDecisionsResponse(decisions)}, nil
}

func parseEvaluationPagination(limitValue, offsetValue string) (int, int) {
	limit := 50
	offset := 0

	if n, ok := positiveInt(limitValue); ok {
		limit = n
	}
	if n, ok := nonNegativeInt(offsetValue); ok {
		offset = n
	}

	return limit, offset
}

func positiveInt(value string) (int, bool) {
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func nonNegativeInt(value string) (int, bool) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
