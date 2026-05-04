package ingest

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/ingestgrpc"
	"github.com/danielterry/dependency-firewall/internal/infra/controlplanegrpc"
)

type grpcDecisionRepository struct {
	decision domain.Decision
}

func (r *grpcDecisionRepository) Record(_ context.Context, decision *domain.Decision) error {
	decision.ID = "decision-123"
	decision.EvaluatedAt = time.Date(2026, time.May, 3, 16, 10, 0, 0, time.UTC)
	r.decision = *decision
	return nil
}

func (r *grpcDecisionRepository) GetByArtifact(_ context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	if r.decision.TenantID != tenantID || r.decision.Artifact.Name != artifact.Name {
		return nil, domain.ErrArtifactNotFound
	}
	decision := r.decision
	return &decision, nil
}

func (r *grpcDecisionRepository) ListByTenant(context.Context, string, int, int, string) ([]domain.Decision, error) {
	return []domain.Decision{r.decision}, nil
}

func (r *grpcDecisionRepository) HasRecentAllow(_ context.Context, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	return r.decision.TenantID == tenantID && r.decision.Artifact.Ecosystem == ecosystem && r.decision.Artifact.Namespace == namespace && r.decision.Artifact.Name == name && r.decision.Outcome == domain.DecisionAllow, nil
}

type grpcAuditRecorder struct {
	event domain.AuditEvent
}

func (r *grpcAuditRecorder) Record(_ context.Context, event *domain.AuditEvent) error {
	r.event = *event
	return nil
}

func TestGRPCClient_DecisionRepositoryAndAuditRecorder(t *testing.T) {
	t.Parallel()

	listener := bufconn.Listen(1024 * 1024)
	decisionRepo := &grpcDecisionRepository{}
	auditRecorder := &grpcAuditRecorder{}
	grpcServer := grpc.NewServer(controlplanegrpc.ServerOptions()...)
	ingestgrpc.NewServer(service.NewProxyIngestService(decisionRepo, auditRecorder)).Register(grpcServer)
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		append([]grpc.DialOption{
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
		}, controlplanegrpc.DialOptions()...)...,
	)
	require.NoError(t, err)
	defer conn.Close()

	client := &GRPCClient{conn: conn}
	decisionAdapter := NewDecisionRepository(client)
	auditAdapter := NewAuditEventRecorder(client)

	decision := &domain.Decision{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{Ecosystem: domain.EcosystemOCI, Namespace: "acme", Name: "app", Digest: "sha256:abc"},
		Outcome:  domain.DecisionAllow,
		Reason:   "ok",
		Reasons: []domain.EvaluationReason{{
			PolicyID:   "policy-1",
			PolicyName: "allow app",
			Category:   domain.ReasonPolicyMatch,
			Action:     domain.PolicyActionAllow,
			Message:    "allowed",
		}},
	}
	require.NoError(t, decisionAdapter.Record(context.Background(), decision))
	assert.Equal(t, "decision-123", decision.ID)
	assert.Equal(t, decision.ID, decisionRepo.decision.ID)
	assert.Equal(t, decision.Artifact.Name, decisionRepo.decision.Artifact.Name)

	persisted, err := decisionAdapter.GetByArtifact(context.Background(), "tenant-1", decision.Artifact)
	require.NoError(t, err)
	assert.Equal(t, decisionRepo.decision.Reason, persisted.Reason)

	listed, err := decisionAdapter.ListByTenant(context.Background(), "tenant-1", 10, 0, "")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, decisionRepo.decision.TenantID, listed[0].TenantID)

	allowed, err := decisionAdapter.HasRecentAllow(context.Background(), "tenant-1", domain.EcosystemOCI, "acme", "app")
	require.NoError(t, err)
	assert.True(t, allowed)

	event := &domain.AuditEvent{
		TenantID:      "tenant-1",
		CorrelationID: "req-1",
		EventType:     domain.AuditEventDecisionPersisted,
		Source:        "core/access",
		Outcome:       domain.DecisionAllow,
		Artifact:      decision.Artifact,
		Message:       "decision persisted",
		Payload:       map[string]any{"policy_hash": "hash-1"},
		CreatedAt:     time.Date(2026, time.May, 3, 16, 11, 0, 0, time.UTC),
	}
	require.NoError(t, auditAdapter.Record(context.Background(), event))
	assert.Equal(t, event.CorrelationID, auditRecorder.event.CorrelationID)
	assert.Equal(t, event.Payload["policy_hash"], auditRecorder.event.Payload["policy_hash"])
}

func TestGRPCClient_MapsArtifactNotFound(t *testing.T) {
	t.Parallel()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer(controlplanegrpc.ServerOptions()...)
	ingestgrpc.NewServer(service.NewProxyIngestService(&grpcDecisionRepository{}, &grpcAuditRecorder{})).Register(grpcServer)
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		append([]grpc.DialOption{
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
		}, controlplanegrpc.DialOptions()...)...,
	)
	require.NoError(t, err)
	defer conn.Close()

	client := &GRPCClient{conn: conn}
	_, err = client.GetDecisionByArtifact(context.Background(), "tenant-1", domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "missing"})
	require.ErrorIs(t, err, domain.ErrArtifactNotFound)
}
