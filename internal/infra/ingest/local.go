package ingest

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// LocalDecisionRepository adapts an in-process ProxyIngestService to the proxy decision repository port.
type LocalDecisionRepository struct {
	service *service.ProxyIngestService
}

// NewLocalDecisionRepository creates a new in-process decision repository adapter.
func NewLocalDecisionRepository(service *service.ProxyIngestService) *LocalDecisionRepository {
	return &LocalDecisionRepository{service: service}
}

// Record persists a decision through the in-process control-plane ingestion service.
func (r *LocalDecisionRepository) Record(ctx context.Context, decision *domain.Decision) error {
	if r == nil || r.service == nil {
		return fmt.Errorf("recording decision: service unavailable")
	}
	return r.service.RecordDecision(ctx, decision)
}

// GetByArtifact fetches the most recent decision for an artifact.
func (r *LocalDecisionRepository) GetByArtifact(
	ctx context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.Decision, error) {
	if r == nil || r.service == nil {
		return nil, fmt.Errorf("getting decision by artifact: service unavailable")
	}
	return r.service.GetDecisionByArtifact(ctx, tenantID, artifact)
}

// ListByTenant lists decisions for a tenant.
func (r *LocalDecisionRepository) ListByTenant(
	ctx context.Context,
	tenantID string,
	limit, offset int,
	search string,
) ([]domain.Decision, error) {
	if r == nil || r.service == nil {
		return nil, fmt.Errorf("listing decisions: service unavailable")
	}
	return r.service.ListDecisionsByTenant(ctx, tenantID, limit, offset, search)
}

// HasRecentAllow checks whether an artifact has a recent allow decision.
func (r *LocalDecisionRepository) HasRecentAllow(
	ctx context.Context,
	tenantID string,
	ecosystem domain.EcosystemType,
	namespace, name string,
) (bool, error) {
	if r == nil || r.service == nil {
		return false, fmt.Errorf("checking recent allow: service unavailable")
	}
	return r.service.HasRecentAllow(ctx, tenantID, ecosystem, namespace, name)
}

// HasRecentAllowInScope performs the has recent allow in scope operation.
func (r *LocalDecisionRepository) HasRecentAllowInScope(
	ctx context.Context,
	scope domain.AuthorizationScope,
	ecosystem domain.EcosystemType,
	namespace, name string,
) (bool, error) {
	if r == nil || r.service == nil {
		return false, fmt.Errorf("checking scoped recent allow: service unavailable")
	}
	return r.service.HasRecentAllowInScope(ctx, scope, ecosystem, namespace, name)
}

// LocalAuditEventRecorder adapts an in-process ProxyIngestService to the audit recorder port.
type LocalAuditEventRecorder struct {
	service *service.ProxyIngestService
}

// NewLocalAuditEventRecorder creates a new in-process audit recorder adapter.
func NewLocalAuditEventRecorder(service *service.ProxyIngestService) *LocalAuditEventRecorder {
	return &LocalAuditEventRecorder{service: service}
}

// Record persists one audit event through the in-process control-plane ingestion service.
func (r *LocalAuditEventRecorder) Record(ctx context.Context, event *domain.AuditEvent) error {
	if r == nil || r.service == nil {
		return fmt.Errorf("recording audit event: service unavailable")
	}
	return r.service.RecordAuditEvent(ctx, event)
}
