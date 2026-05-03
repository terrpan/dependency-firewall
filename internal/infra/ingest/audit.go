package ingest

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// AuditEventRecorder adapts the proxy ingestion gRPC client to the audit recorder port.
type AuditEventRecorder struct {
	client *GRPCClient
}

// NewAuditEventRecorder creates a new gRPC-backed audit event recorder.
func NewAuditEventRecorder(client *GRPCClient) *AuditEventRecorder {
	return &AuditEventRecorder{client: client}
}

// Record persists one audit event through the control-plane ingestion service.
func (r *AuditEventRecorder) Record(ctx context.Context, event *domain.AuditEvent) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("recording audit event: client unavailable")
	}
	return r.client.RecordAuditEvent(ctx, event)
}
