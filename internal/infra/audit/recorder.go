package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// FanoutRecorder writes audit events to multiple sinks.
type FanoutRecorder struct {
	recorders []port.AuditEventRecorder
}

// NewFanoutRecorder creates a recorder that fans out to all provided sinks.
func NewFanoutRecorder(recorders ...port.AuditEventRecorder) *FanoutRecorder {
	filtered := make([]port.AuditEventRecorder, 0, len(recorders))
	for _, recorder := range recorders {
		if recorder != nil {
			filtered = append(filtered, recorder)
		}
	}
	return &FanoutRecorder{recorders: filtered}
}

// Record writes the event to each configured recorder.
func (r *FanoutRecorder) Record(ctx context.Context, event *domain.AuditEvent) error {
	var failures []string
	for _, recorder := range r.recorders {
		if err := recorder.Record(ctx, event); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("recording audit event: %s", strings.Join(failures, "; "))
	}
	return nil
}

// SlogRecorder writes audit events to the application logger as structured records.
type SlogRecorder struct {
	logger *slog.Logger
}

// NewSlogRecorder creates a slog-backed audit recorder.
func NewSlogRecorder(logger *slog.Logger) *SlogRecorder {
	return &SlogRecorder{logger: logger}
}

// Record writes one structured audit event to slog.
func (r *SlogRecorder) Record(ctx context.Context, event *domain.AuditEvent) error {
	if r == nil || r.logger == nil || event == nil {
		return nil
	}

	attrs := []any{
		"audit", true,
		"event_type", event.EventType,
		"tenant_id", event.TenantID,
		"correlation_id", event.CorrelationID,
		"source", event.Source,
		"entity_type", event.EntityType,
		"entity_id", event.EntityID,
		"upstream_id", event.UpstreamID,
		"policy_id", event.PolicyID,
		"outcome", event.Outcome,
		"artifact", event.Artifact,
		"payload", event.Payload,
	}
	message := strings.TrimSpace(event.Message)
	if message == "" {
		message = string(event.EventType)
	}
	r.logger.InfoContext(ctx, message, attrs...)
	return nil
}
