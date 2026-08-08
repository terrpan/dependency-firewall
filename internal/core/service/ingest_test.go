package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type ingestDecisionRepository struct {
	decision *domain.Decision
}

func (r *ingestDecisionRepository) Record(_ context.Context, decision *domain.Decision) error {
	r.decision = &domain.Decision{}
	*r.decision = *decision
	decision.ID = "decision-1"
	decision.EvaluatedAt = time.Date(2026, time.May, 3, 15, 0, 0, 0, time.UTC)
	return nil
}

func (r *ingestDecisionRepository) GetByArtifact(context.Context, string, domain.ArtifactIdentity) (*domain.Decision, error) {
	return r.decision, nil
}

func (r *ingestDecisionRepository) ListByTenant(context.Context, string, int, int, string) ([]domain.Decision, error) {
	if r.decision == nil {
		return nil, nil
	}
	return []domain.Decision{*r.decision}, nil
}

func (r *ingestDecisionRepository) HasRecentAllow(context.Context, string, domain.EcosystemType, string, string) (bool, error) {
	return true, nil
}

type ingestAuditRecorder struct {
	event *domain.AuditEvent
}

func (r *ingestAuditRecorder) Record(_ context.Context, event *domain.AuditEvent) error {
	r.event = &domain.AuditEvent{}
	*r.event = *event
	return nil
}

type ingestGraphStore struct {
	dependencyContext *domain.DependencyContext
}

func (s *ingestGraphStore) EnqueueResolve(context.Context, domain.DependencyGraphResolveRequest) (bool, error) {
	return true, nil
}

func (s *ingestGraphStore) LookupContext(context.Context, domain.DependencyContextSummaryKey) (*domain.DependencyContext, error) {
	if s.dependencyContext == nil {
		return nil, domain.ErrArtifactNotFound
	}
	return s.dependencyContext, nil
}

func TestProxyIngestService_LookupDependencyGraphContext(t *testing.T) {
	t.Parallel()

	dependencyContext := domain.DependencyContext{Scope: domain.DependencyScopeDirect}.Normalize()
	store := &ingestGraphStore{dependencyContext: &dependencyContext}
	svc := NewProxyIngestService(nil, nil, store, nil)

	result, err := svc.LookupDependencyGraphContext(context.Background(), domain.DependencyContextSummaryKey{
		TenantID: "tenant-1",
	})
	require.NoError(t, err)
	assert.Equal(t, domain.DependencyScopeDirect, result.Scope)

	_, err = svc.LookupDependencyGraphContext(context.Background(), domain.DependencyContextSummaryKey{})
	require.Error(t, err)
}

func TestProxyIngestService_LookupDependencyGraphContext_Unavailable(t *testing.T) {
	t.Parallel()

	svc := NewProxyIngestService(nil, nil, nil, nil)
	_, err := svc.LookupDependencyGraphContext(context.Background(), domain.DependencyContextSummaryKey{TenantID: "tenant-1"})
	require.Error(t, err)
}

func TestProxyIngestService_PersistsDecisionAndAuditEvent(t *testing.T) {
	t.Parallel()

	decisionRepo := &ingestDecisionRepository{}
	auditRecorder := &ingestAuditRecorder{}
	service := NewProxyIngestService(decisionRepo, auditRecorder, nil, nil)

	decision := &domain.Decision{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "left-pad", Version: "1.0.0"},
		Outcome:  domain.DecisionAllow,
		Reason:   "ok",
	}
	require.NoError(t, service.RecordDecision(context.Background(), decision))
	assert.Equal(t, "decision-1", decision.ID)
	assert.False(t, decision.EvaluatedAt.IsZero())
	require.NotNil(t, decisionRepo.decision)
	assert.Equal(t, "tenant-1", decisionRepo.decision.TenantID)

	event := &domain.AuditEvent{
		TenantID:  "tenant-1",
		EventType: domain.AuditEventDecisionPersisted,
		Message:   "decision persisted",
	}
	require.NoError(t, service.RecordAuditEvent(context.Background(), event))
	require.NotNil(t, auditRecorder.event)
	assert.Equal(t, domain.AuditEventDecisionPersisted, auditRecorder.event.EventType)

	allowed, err := service.HasRecentAllow(context.Background(), "tenant-1", domain.EcosystemNPM, "", "left-pad")
	require.NoError(t, err)
	assert.True(t, allowed)
}
