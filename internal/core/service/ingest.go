package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// ProxyIngestService owns control-plane persistence workflows initiated by proxies.
type ProxyIngestService struct {
	decisions port.DecisionRepository
	audits    port.AuditEventRecorder
}

// NewProxyIngestService creates a new ProxyIngestService.
func NewProxyIngestService(decisions port.DecisionRepository, audits port.AuditEventRecorder) *ProxyIngestService {
	return &ProxyIngestService{
		decisions: decisions,
		audits:    audits,
	}
}

// RecordDecision persists a proxy-evaluated decision through the authoritative repository.
func (s *ProxyIngestService) RecordDecision(ctx context.Context, decision *domain.Decision) error {
	if s == nil || s.decisions == nil {
		return fmt.Errorf("recording decision: repository unavailable")
	}
	if decision == nil {
		return fmt.Errorf("recording decision: decision is required")
	}
	if strings.TrimSpace(decision.TenantID) == "" {
		return fmt.Errorf("recording decision: tenant_id is required")
	}
	return s.decisions.Record(ctx, decision)
}

// GetDecisionByArtifact loads a persisted decision for a tenant artifact.
func (s *ProxyIngestService) GetDecisionByArtifact(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	if s == nil || s.decisions == nil {
		return nil, fmt.Errorf("getting decision by artifact: repository unavailable")
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("getting decision by artifact: tenant_id is required")
	}
	return s.decisions.GetByArtifact(ctx, tenantID, artifact)
}

// ListDecisionsByTenant lists persisted decisions for a tenant.
func (s *ProxyIngestService) ListDecisionsByTenant(ctx context.Context, tenantID string, limit, offset int, search string) ([]domain.Decision, error) {
	if s == nil || s.decisions == nil {
		return nil, fmt.Errorf("listing decisions: repository unavailable")
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("listing decisions: tenant_id is required")
	}
	return s.decisions.ListByTenant(ctx, tenantID, limit, offset, search)
}

// HasRecentAllow reports whether a tenant artifact has a recent allow decision.
func (s *ProxyIngestService) HasRecentAllow(ctx context.Context, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	if s == nil || s.decisions == nil {
		return false, fmt.Errorf("checking recent allow: repository unavailable")
	}
	if strings.TrimSpace(tenantID) == "" {
		return false, fmt.Errorf("checking recent allow: tenant_id is required")
	}
	return s.decisions.HasRecentAllow(ctx, tenantID, ecosystem, namespace, name)
}

// RecordAuditEvent persists a proxy-emitted audit event through the authoritative recorder.
func (s *ProxyIngestService) RecordAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	if s == nil || s.audits == nil {
		return fmt.Errorf("recording audit event: recorder unavailable")
	}
	if event == nil {
		return fmt.Errorf("recording audit event: event is required")
	}
	if strings.TrimSpace(event.TenantID) == "" {
		return fmt.Errorf("recording audit event: tenant_id is required")
	}
	return s.audits.Record(ctx, event)
}
