package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/errutil"
	"go.opentelemetry.io/otel/attribute"
)

// AuditService owns audit event emission and read-side access for the control plane.
type AuditService struct {
	recorder    port.AuditEventRecorder
	repo        port.AuditEventRepository
	logger      *slog.Logger
	enabled     bool
	failureMode domain.AuditFailureMode
	detailLevel domain.AuditDetailLevel
}

// NewAuditService creates a new AuditService.
func NewAuditService(
	recorder port.AuditEventRecorder,
	repo port.AuditEventRepository,
	logger *slog.Logger,
	enabled bool,
	failureMode domain.AuditFailureMode,
	detailLevel domain.AuditDetailLevel,
) *AuditService {
	return &AuditService{
		recorder:    recorder,
		repo:        repo,
		logger:      logger,
		enabled:     enabled,
		failureMode: failureMode,
		detailLevel: detailLevel,
	}
}

// Enabled reports whether audit capture is active.
func (s *AuditService) Enabled() bool {
	return s != nil && s.enabled
}

// DetailLevel reports the configured audit payload detail level.
func (s *AuditService) DetailLevel() domain.AuditDetailLevel {
	if s == nil || s.detailLevel == "" {
		return domain.AuditDetailLevelSummary
	}
	return s.detailLevel
}

// Record writes an audit event through the configured recorder.
func (s *AuditService) Record(ctx context.Context, event domain.AuditEvent) error {
	if s == nil || !s.enabled || s.recorder == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		if errutil.IsCanceled(err) {
			return nil
		}
	}

	ctx, span := serviceTracer().Start(ctx, "audit.record")
	span.SetAttributes(
		attribute.String("tenant.id", event.TenantID),
		attribute.String("audit.event_type", string(event.EventType)),
		attribute.String("audit.source", event.Source),
	)
	if event.CorrelationID != "" {
		span.SetAttributes(attribute.String("request.id", event.CorrelationID))
	}
	defer span.End()

	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}

	if err := s.recorder.Record(ctx, &event); err != nil {
		if errutil.IsCanceled(err) {
			return nil
		}
		recordSpanErrorIfUnexpected(span, err)
		if s.logger != nil {
			s.logger.ErrorContext(ctx, "writing audit event",
				"error", err,
				"tenant_id", event.TenantID,
				"correlation_id", event.CorrelationID,
				"event_type", event.EventType,
			)
		}
		if s.failureMode == domain.AuditFailureModeFailClosed {
			return domain.ErrAuditUnavailable
		}
	}

	return nil
}

// ListByTenant returns persisted audit events for a tenant.
func (s *AuditService) ListByTenant(ctx context.Context, filter domain.AuditEventFilter) ([]domain.AuditEvent, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("listing audit events: repository unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, span := serviceTracer().Start(ctx, "audit.list")
	span.SetAttributes(attribute.String("tenant.id", filter.TenantID))
	defer span.End()

	events, err := s.repo.ListByTenant(ctx, filter)
	if err != nil {
		recordSpanErrorIfUnexpected(span, err)
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	return events, nil
}
