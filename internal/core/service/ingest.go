package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// ProxyIngestService owns control-plane persistence workflows initiated by proxies.
type ProxyIngestService struct {
	decisions     port.DecisionRepository
	audits        port.AuditEventRecorder
	graphs        port.DependencyGraphQueue
	graphResolver port.DependencyGraphResolver
	graphContexts port.DependencyGraphContextLookup
	graphNotifier *DependencyGraphJobNotifier
}

// NewProxyIngestService creates a new ProxyIngestService. graphs and notifier
// may be nil when the runtime does not process dependency graph jobs.
func NewProxyIngestService(decisions port.DecisionRepository, audits port.AuditEventRecorder, graphs port.DependencyGraphQueue, notifier *DependencyGraphJobNotifier) *ProxyIngestService {
	var graphResolver port.DependencyGraphResolver
	if resolver, ok := graphs.(port.DependencyGraphResolver); ok {
		graphResolver = resolver
	}
	var graphContexts port.DependencyGraphContextLookup
	if contexts, ok := graphs.(port.DependencyGraphContextLookup); ok {
		graphContexts = contexts
	}
	return &ProxyIngestService{
		decisions:     decisions,
		audits:        audits,
		graphs:        graphs,
		graphResolver: graphResolver,
		graphContexts: graphContexts,
		graphNotifier: notifier,
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

// EnqueueDependencyGraphResolve persists an async graph-resolution request.
func (s *ProxyIngestService) EnqueueDependencyGraphResolve(ctx context.Context, req domain.DependencyGraphResolveRequest) (bool, error) {
	if s == nil || s.graphs == nil {
		return false, fmt.Errorf("enqueueing dependency graph resolve: queue unavailable")
	}
	if strings.TrimSpace(req.TenantID) == "" {
		return false, fmt.Errorf("enqueueing dependency graph resolve: tenant_id is required")
	}
	enqueued, err := s.graphs.EnqueueResolve(ctx, req)
	if err == nil && enqueued {
		s.graphNotifier.Notify(req.TenantID)
	}
	return enqueued, err
}

// WatchDependencyGraphResolve streams wake-up signals emitted when graph jobs are enqueued.
func (s *ProxyIngestService) WatchDependencyGraphResolve(ctx context.Context, tenantID string) (<-chan struct{}, error) {
	if s == nil || s.graphNotifier == nil {
		return nil, fmt.Errorf("watching dependency graph resolve: notifier unavailable")
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("watching dependency graph resolve: tenant_id is required")
	}
	return s.graphNotifier.WatchResolveJobs(ctx, tenantID), nil
}

// LookupDependencyGraphContext loads the graph context summary for a tenant artifact.
func (s *ProxyIngestService) LookupDependencyGraphContext(ctx context.Context, key domain.DependencyContextSummaryKey) (*domain.DependencyContext, error) {
	if s == nil || s.graphContexts == nil {
		return nil, fmt.Errorf("looking up dependency graph context: lookup unavailable")
	}
	if strings.TrimSpace(key.TenantID) == "" {
		return nil, fmt.Errorf("looking up dependency graph context: tenant_id is required")
	}
	return s.graphContexts.LookupContext(ctx, key)
}

// ClaimDependencyGraphResolve claims the next retryable resolver job.
func (s *ProxyIngestService) ClaimDependencyGraphResolve(ctx context.Context, tenantID string, now time.Time) (*domain.DependencyGraphResolveRequest, error) {
	if s == nil || s.graphResolver == nil {
		return nil, fmt.Errorf("claiming dependency graph resolve: resolver unavailable")
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("claiming dependency graph resolve: tenant_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return s.graphResolver.ClaimNextResolveJob(ctx, tenantID, now)
}

// CompleteDependencyGraphResolve persists the graph produced by a resolver worker.
func (s *ProxyIngestService) CompleteDependencyGraphResolve(ctx context.Context, req domain.DependencyGraphResolveRequest, nodes []domain.DependencyGraphNode, edges []domain.DependencyGraphEdge, graphHash string) error {
	if s == nil || s.graphResolver == nil {
		return fmt.Errorf("completing dependency graph resolve: resolver unavailable")
	}
	if strings.TrimSpace(req.TenantID) == "" {
		return fmt.Errorf("completing dependency graph resolve: tenant_id is required")
	}
	if strings.TrimSpace(graphHash) == "" {
		return fmt.Errorf("completing dependency graph resolve: graph_hash is required")
	}
	return s.graphResolver.CompleteResolve(ctx, req, nodes, edges, graphHash)
}

// FailDependencyGraphResolve records a resolver failure and retry time.
func (s *ProxyIngestService) FailDependencyGraphResolve(ctx context.Context, req domain.DependencyGraphResolveRequest, message string, retryAfter time.Time) error {
	if s == nil || s.graphResolver == nil {
		return fmt.Errorf("failing dependency graph resolve: resolver unavailable")
	}
	if strings.TrimSpace(req.TenantID) == "" {
		return fmt.Errorf("failing dependency graph resolve: tenant_id is required")
	}
	if retryAfter.IsZero() {
		return fmt.Errorf("failing dependency graph resolve: retry_after is required")
	}
	return s.graphResolver.FailResolve(ctx, req, message, retryAfter)
}
