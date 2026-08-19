package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

type localDecisionRepository struct {
	decision domain.Decision
}

func (r *localDecisionRepository) Record(_ context.Context, decision *domain.Decision) error {
	decision.ID = "decision-123"
	decision.EvaluatedAt = time.Date(2026, time.May, 4, 12, 0, 0, 0, time.UTC)
	r.decision = *decision
	return nil
}

func (r *localDecisionRepository) GetByArtifact(
	_ context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.Decision, error) {
	if r.decision.TenantID != tenantID || r.decision.Artifact != artifact {
		return nil, domain.ErrArtifactNotFound
	}
	decision := r.decision
	return &decision, nil
}

func (r *localDecisionRepository) ListByTenant(context.Context, string, int, int, string) ([]domain.Decision, error) {
	return []domain.Decision{r.decision}, nil
}

func (r *localDecisionRepository) HasRecentAllow(
	_ context.Context,
	tenantID string,
	ecosystem domain.EcosystemType,
	namespace, name string,
) (bool, error) {
	return r.decision.TenantID == tenantID &&
		r.decision.Artifact.Ecosystem == ecosystem &&
		r.decision.Artifact.Namespace == namespace &&
		r.decision.Artifact.Name == name &&
		r.decision.Outcome == domain.DecisionAllow, nil
}

type localAuditRecorder struct {
	event domain.AuditEvent
}

func (r *localAuditRecorder) Record(_ context.Context, event *domain.AuditEvent) error {
	r.event = *event
	return nil
}

func TestLocalAdapters_ProxyIngestService(t *testing.T) {
	t.Parallel()

	decisionRepo := &localDecisionRepository{}
	auditRecorder := &localAuditRecorder{}
	ingestService := service.NewProxyIngestService(decisionRepo, auditRecorder, nil, nil)

	decisionAdapter := NewLocalDecisionRepository(ingestService)
	auditAdapter := NewLocalAuditEventRecorder(ingestService)

	decision := &domain.Decision{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Namespace: "acme",
			Name:      "app",
			Digest:    "sha256:abc",
		},
		Outcome: domain.DecisionAllow,
		Reason:  "ok",
	}
	require.NoError(t, decisionAdapter.Record(context.Background(), decision))
	assert.Equal(t, "decision-123", decision.ID)

	persisted, err := decisionAdapter.GetByArtifact(context.Background(), "tenant-1", decision.Artifact)
	require.NoError(t, err)
	assert.Equal(t, decision.ID, persisted.ID)

	listed, err := decisionAdapter.ListByTenant(context.Background(), "tenant-1", 10, 0, "")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, decision.ID, listed[0].ID)

	allowed, err := decisionAdapter.HasRecentAllow(context.Background(), "tenant-1", domain.EcosystemOCI, "acme", "app")
	require.NoError(t, err)
	assert.True(t, allowed)

	event := &domain.AuditEvent{
		TenantID:      "tenant-1",
		CorrelationID: "req-1",
		EventType:     domain.AuditEventDecisionPersisted,
		Artifact:      decision.Artifact,
		Message:       "decision persisted",
	}
	require.NoError(t, auditAdapter.Record(context.Background(), event))
	assert.Equal(t, "req-1", auditRecorder.event.CorrelationID)
	assert.Equal(t, decision.Artifact.Digest, auditRecorder.event.Artifact.Digest)
}
