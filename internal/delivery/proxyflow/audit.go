package proxyflow

import (
	"context"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type AuditRecorder interface {
	Record(ctx context.Context, event domain.AuditEvent) error
}

type AuditContext struct {
	TenantID      string
	CorrelationID string
	Source        string
	UpstreamID    string
	Artifact      domain.ArtifactIdentity
	Operation     string
}

func RecordRequestReceived(ctx context.Context, recorder AuditRecorder, audit AuditContext, r *http.Request, message string, extraPayload map[string]any) error {
	payload := basePayload(audit.Operation)
	payload["method"] = r.Method
	payload["path"] = r.URL.Path
	payload["remote_addr"] = r.RemoteAddr
	mergePayload(payload, extraPayload)
	return record(ctx, recorder, domain.AuditEvent{
		TenantID:      audit.TenantID,
		CorrelationID: audit.CorrelationID,
		EventType:     domain.AuditEventProxyRequestReceived,
		Source:        audit.Source,
		UpstreamID:    audit.UpstreamID,
		Artifact:      audit.Artifact,
		Message:       message,
		Payload:       payload,
	})
}

func RecordRequestDenied(ctx context.Context, recorder AuditRecorder, audit AuditContext, decision *domain.Decision, message string) error {
	return record(ctx, recorder, requestAuditEvent(
		audit,
		domain.AuditEventRequestDenied,
		message,
		decision,
		map[string]any{
			"reason":  decision.Reason,
			"reasons": decision.Reasons,
		},
	))
}

func RecordRequestAllowed(ctx context.Context, recorder AuditRecorder, audit AuditContext, decision *domain.Decision, message string) error {
	return record(ctx, recorder, requestAuditEvent(
		audit,
		domain.AuditEventRequestAllowed,
		message,
		decision,
		map[string]any{
			"warnings": decision.Warnings,
			"reasons":  decision.Reasons,
		},
	))
}

func RecordRequestForwarded(ctx context.Context, recorder AuditRecorder, audit AuditContext, decision *domain.Decision, reason, message string) error {
	payload := map[string]any{"reason": reason}
	if decision != nil {
		payload["evaluation_outcome"] = decision.Outcome
		payload["warnings"] = decision.Warnings
		payload["reasons"] = decision.Reasons
	}
	event := requestAuditEvent(audit, domain.AuditEventRequestForwarded, message, nil, payload)
	if decision != nil {
		event.Artifact = decision.Artifact
	}
	return record(ctx, recorder, event)
}

func RecordSimpleRequestAllowed(ctx context.Context, recorder AuditRecorder, audit AuditContext, message string) error {
	return record(ctx, recorder, requestAuditEvent(audit, domain.AuditEventRequestAllowed, message, nil, nil))
}

func RecordSimpleRequestDenied(ctx context.Context, recorder AuditRecorder, audit AuditContext, reason, message string) error {
	return record(ctx, recorder, requestAuditEvent(
		audit,
		domain.AuditEventRequestDenied,
		message,
		nil,
		map[string]any{"reason": reason},
	))
}

func RecordUpstreamFetchStarted(ctx context.Context, recorder AuditRecorder, audit AuditContext, message string) error {
	return record(ctx, recorder, domain.AuditEvent{
		TenantID:      audit.TenantID,
		CorrelationID: audit.CorrelationID,
		EventType:     domain.AuditEventUpstreamFetchStarted,
		Source:        audit.Source,
		UpstreamID:    audit.UpstreamID,
		Artifact:      audit.Artifact,
		Message:       message,
		Payload:       basePayload(audit.Operation),
	})
}

func RecordUpstreamFetchFailed(ctx context.Context, recorder AuditRecorder, audit AuditContext, message string, err error) error {
	return record(ctx, recorder, domain.AuditEvent{
		TenantID:      audit.TenantID,
		CorrelationID: audit.CorrelationID,
		EventType:     domain.AuditEventUpstreamFetchFailed,
		Source:        audit.Source,
		UpstreamID:    audit.UpstreamID,
		Artifact:      audit.Artifact,
		Message:       message,
		Payload: map[string]any{
			"operation": audit.Operation,
			"error":     err.Error(),
		},
	})
}

func record(ctx context.Context, recorder AuditRecorder, event domain.AuditEvent) error {
	if recorder == nil {
		return nil
	}
	return recorder.Record(ctx, event)
}

func requestAuditEvent(
	audit AuditContext,
	eventType domain.AuditEventType,
	message string,
	decision *domain.Decision,
	extraPayload map[string]any,
) domain.AuditEvent {
	event := domain.AuditEvent{
		TenantID:      audit.TenantID,
		CorrelationID: audit.CorrelationID,
		EventType:     eventType,
		Source:        audit.Source,
		UpstreamID:    audit.UpstreamID,
		Message:       message,
		Artifact:      audit.Artifact,
		Payload:       basePayload(audit.Operation),
	}

	if decision != nil {
		event.EntityType = "decision"
		event.EntityID = decision.ID
		event.PolicyID = decision.PolicyID
		event.Outcome = decision.Outcome
		event.Artifact = decision.Artifact
	}

	mergePayload(event.Payload, extraPayload)
	return event
}

func basePayload(operation string) map[string]any {
	return map[string]any{"operation": operation}
}

func mergePayload(payload, extra map[string]any) {
	for key, value := range extra {
		payload[key] = value
	}
}
