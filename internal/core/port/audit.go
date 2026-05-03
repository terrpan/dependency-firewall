package port

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// AuditEventRecorder writes append-only audit events to one or more sinks.
type AuditEventRecorder interface {
	Record(ctx context.Context, event *domain.AuditEvent) error
}

// AuditEventRepository lists tenant-scoped persisted audit events.
type AuditEventRepository interface {
	ListByTenant(ctx context.Context, filter domain.AuditEventFilter) ([]domain.AuditEvent, error)
}
