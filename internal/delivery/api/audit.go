package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// AuditHandler handles audit event listing endpoints.
type AuditHandler struct {
	audits *service.AuditService
	logger *slog.Logger
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(audits *service.AuditService, logger *slog.Logger) *AuditHandler {
	return &AuditHandler{audits: audits, logger: logger}
}

// RegisterHumaRoutes registers audit routes on the control-plane Huma API.
func (h *AuditHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-audit-events",
		Method:      http.MethodGet,
		Path:        "/api/v1/audit/events",
		Summary:     "List audit events",
		Description: "Lists tenant-scoped audit events for evaluation, proxy, and decision workflows with structured filtering options.",
		Tags:        []string{"audit"},
		Errors:      controlPlaneReadErrors(http.StatusBadRequest, http.StatusInternalServerError),
	}, h.listHuma)
	removeValidationResponse(api, "/api/v1/audit/events", http.MethodGet)
}

type auditListInput struct {
	TenantID      string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	Limit         string `                     doc:"Maximum audit events to return"                                                                            query:"limit"`
	Offset        string `                     doc:"Audit events to skip"                                                                                      query:"offset"`
	Search        string `                     doc:"Case-insensitive search across event type, message, correlation ID, policy, upstream, and artifact fields" query:"search"`
	EventType     string `                     doc:"Exact audit event type filter"                                                                             query:"event_type"`
	Outcome       string `                     doc:"Exact decision outcome filter"                                                                             query:"outcome"`
	CorrelationID string `                     doc:"Exact request correlation identifier"                                                                      query:"correlation_id"`
	PolicyID      string `                     doc:"Exact policy identifier"                                                                                   query:"policy_id"`
	Source        string `                     doc:"Exact source filter such as delivery/npm or core/access"                                                   query:"source"`
	Since         string `                     doc:"Inclusive RFC3339 lower bound for created_at"                                                              query:"since"`
	Until         string `                     doc:"Inclusive RFC3339 upper bound for created_at"                                                              query:"until"`
}

type auditListOutput struct {
	Body []*AuditEventResponse
}

func (h *AuditHandler) listHuma(ctx context.Context, input *auditListInput) (*auditListOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	since, err := parseRFC3339Query(input.Since, "since")
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	until, err := parseRFC3339Query(input.Until, "until")
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()

	events, err := h.audits.ListByTenant(ctx, domain.AuditEventFilter{
		TenantID:      tenantID,
		Limit:         parseAuditLimit(input.Limit),
		Offset:        parseAuditOffset(input.Offset),
		Search:        strings.TrimSpace(input.Search),
		EventType:     domain.AuditEventType(strings.TrimSpace(input.EventType)),
		Outcome:       domain.DecisionOutcome(strings.TrimSpace(input.Outcome)),
		CorrelationID: strings.TrimSpace(input.CorrelationID),
		PolicyID:      strings.TrimSpace(input.PolicyID),
		Source:        strings.TrimSpace(input.Source),
		Since:         since,
		Until:         until,
	})
	if err != nil {
		return nil, humaInternalError(
			ctx,
			h.logger,
			"listing audit events",
			err,
			"failed to list audit events",
			"tenant_id",
			tenantID,
		)
	}

	return &auditListOutput{Body: toAuditEventsResponse(events)}, nil
}

func parseAuditLimit(value string) int {
	if n, ok := positiveInt(value); ok {
		return n
	}
	return 50
}

func parseAuditOffset(value string) int {
	if n, ok := nonNegativeInt(value); ok {
		return n
	}
	return 0
}

func parseRFC3339Query(value, field string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be a valid RFC3339 timestamp", field)
	}
	return &parsed, nil
}
