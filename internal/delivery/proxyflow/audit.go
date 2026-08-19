package proxyflow

import (
	"context"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// AuditRecorder is the narrow sink the proxy adapters need to append one audit event. It keeps this package independent
// of how audit records are stored and of the configured audit failure mode, which the implementation owns.
type AuditRecorder interface {
	Record(ctx context.Context, event domain.AuditEvent) error
}

// AuditContext carries the per-request facts that every audit event emitted for a proxy request repeats: the owning
// tenant, the correlation ID shared by those events, the emitting component, the resolved upstream, the artifact under
// evaluation, and the protocol operation recorded in the event payload.
type AuditContext struct {
	TenantID      string
	CorrelationID string
	Source        string
	UpstreamID    string
	Artifact      domain.ArtifactIdentity
	Operation     string
}

// RecordRequestReceived emits the first event of a proxy request, capturing the HTTP method, path and remote address
// alongside any protocol-specific detail in extraPayload. It is recorded before evaluation, so no outcome is known yet.
func RecordRequestReceived(
	ctx context.Context,
	recorder AuditRecorder,
	audit AuditContext,
	r *http.Request,
	message string,
	extraPayload map[string]any,
) error {
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

// RecordRequestDenied records that a request was blocked, linking the event to the persisted decision and retaining
// both the user-facing reason and the full set of contributing policy matches as evidence for the denial.
func RecordRequestDenied(
	ctx context.Context,
	recorder AuditRecorder,
	audit AuditContext,
	decision *domain.Decision,
	message string,
) error {
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

// RecordRequestAllowed records that evaluation permitted the request, retaining the contributing matches and any
// warnings raised by dry-run or unknown-dependency-context policies that did not change the outcome.
func RecordRequestAllowed(
	ctx context.Context,
	recorder AuditRecorder,
	audit AuditContext,
	decision *domain.Decision,
	message string,
) error {
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

// RecordRequestForwarded records that a request was passed through to the upstream, with reason explaining why
// forwarding was chosen. The decision is optional because forwarding can happen without a fresh evaluation; when one is
// supplied its evaluation outcome and evidence are attached and its artifact identity takes precedence.
func RecordRequestForwarded(
	ctx context.Context,
	recorder AuditRecorder,
	audit AuditContext,
	decision *domain.Decision,
	reason, message string,
) error {
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

// RecordSimpleRequestAllowed records an allow for a request that produced no persisted decision, such as a protocol
// endpoint that is not subject to policy evaluation. Only the audit context and message are retained.
func RecordSimpleRequestAllowed(ctx context.Context, recorder AuditRecorder, audit AuditContext, message string) error {
	return record(ctx, recorder, requestAuditEvent(audit, domain.AuditEventRequestAllowed, message, nil, nil))
}

// RecordSimpleRequestDenied records a denial that did not come from policy evaluation, such as a malformed reference or
// an OCI blob without a recent allowing manifest decision. The reason string is the only evidence retained.
func RecordSimpleRequestDenied(
	ctx context.Context,
	recorder AuditRecorder,
	audit AuditContext,
	reason, message string,
) error {
	return record(ctx, recorder, requestAuditEvent(
		audit,
		domain.AuditEventRequestDenied,
		message,
		nil,
		map[string]any{"reason": reason},
	))
}

// RecordUpstreamFetchStarted marks the point where the firewall begins an outbound call to the upstream registry,
// separating time spent in evaluation from time spent waiting on the upstream.
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

// RecordUpstreamFetchFailed records that an outbound upstream call failed, storing the error text so an operator can
// distinguish an upstream availability problem from a policy denial. It does not itself decide how the request ends.
func RecordUpstreamFetchFailed(
	ctx context.Context,
	recorder AuditRecorder,
	audit AuditContext,
	message string,
	err error,
) error {
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
