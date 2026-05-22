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
	"github.com/danielterry/dependency-firewall/internal/infra/controlplanegrpc"
	ingestwire "github.com/danielterry/dependency-firewall/internal/wire/ingestgrpc"
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
	serverOptions, err := controlplanegrpc.ServerOptions()
	require.NoError(t, err)
	grpcServer := grpc.NewServer(serverOptions...)
	registerTestIngestServer(grpcServer, decisionRepo, auditRecorder)
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	dialOptions, err := controlplanegrpc.DialOptions()
	require.NoError(t, err)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		append([]grpc.DialOption{
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
		}, dialOptions...)...,
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
	serverOptions, err := controlplanegrpc.ServerOptions()
	require.NoError(t, err)
	grpcServer := grpc.NewServer(serverOptions...)
	registerTestIngestServer(grpcServer, &grpcDecisionRepository{}, &grpcAuditRecorder{})
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	dialOptions, err := controlplanegrpc.DialOptions()
	require.NoError(t, err)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		append([]grpc.DialOption{
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
		}, dialOptions...)...,
	)
	require.NoError(t, err)
	defer conn.Close()

	client := &GRPCClient{conn: conn}
	_, err = client.GetDecisionByArtifact(context.Background(), "tenant-1", domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "missing"})
	require.ErrorIs(t, err, domain.ErrArtifactNotFound)
}

type testIngestServer struct {
	decisionRepo  *grpcDecisionRepository
	auditRecorder *grpcAuditRecorder
}

func registerTestIngestServer(registrar grpc.ServiceRegistrar, decisionRepo *grpcDecisionRepository, auditRecorder *grpcAuditRecorder) {
	server := &testIngestServer{
		decisionRepo:  decisionRepo,
		auditRecorder: auditRecorder,
	}
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: ingestwire.ServiceName,
		HandlerType: (*testIngestGRPCService)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "RecordDecision", Handler: testRecordDecisionHandler},
			{MethodName: "GetDecisionByArtifact", Handler: testGetDecisionByArtifactHandler},
			{MethodName: "ListDecisionsByTenant", Handler: testListDecisionsByTenantHandler},
			{MethodName: "HasRecentAllow", Handler: testHasRecentAllowHandler},
			{MethodName: "RecordAuditEvent", Handler: testRecordAuditEventHandler},
		},
	}, server)
}

type testIngestGRPCService interface {
	RecordDecision(context.Context, *ingestwire.RecordDecisionRequest) (*ingestwire.RecordDecisionResponse, error)
	GetDecisionByArtifact(context.Context, *ingestwire.GetDecisionByArtifactRequest) (*ingestwire.GetDecisionByArtifactResponse, error)
	ListDecisionsByTenant(context.Context, *ingestwire.ListDecisionsByTenantRequest) (*ingestwire.ListDecisionsByTenantResponse, error)
	HasRecentAllow(context.Context, *ingestwire.HasRecentAllowRequest) (*ingestwire.HasRecentAllowResponse, error)
	RecordAuditEvent(context.Context, *ingestwire.RecordAuditEventRequest) (*ingestwire.RecordAuditEventResponse, error)
}

func (s *testIngestServer) RecordDecision(ctx context.Context, req *ingestwire.RecordDecisionRequest) (*ingestwire.RecordDecisionResponse, error) {
	decision, err := req.Decision.ToDomain()
	if err != nil {
		return nil, err
	}
	if err := s.decisionRepo.Record(ctx, decision); err != nil {
		return nil, ingestwire.ToStatusError(err)
	}
	return &ingestwire.RecordDecisionResponse{Decision: ingestwire.FromDomainDecision(decision)}, nil
}

func (s *testIngestServer) GetDecisionByArtifact(ctx context.Context, req *ingestwire.GetDecisionByArtifactRequest) (*ingestwire.GetDecisionByArtifactResponse, error) {
	decision, err := s.decisionRepo.GetByArtifact(ctx, req.TenantID, req.Artifact.ToDomain())
	if err != nil {
		return nil, ingestwire.ToStatusError(err)
	}
	return &ingestwire.GetDecisionByArtifactResponse{Decision: ingestwire.FromDomainDecision(decision)}, nil
}

func (s *testIngestServer) ListDecisionsByTenant(ctx context.Context, req *ingestwire.ListDecisionsByTenantRequest) (*ingestwire.ListDecisionsByTenantResponse, error) {
	decisions, err := s.decisionRepo.ListByTenant(ctx, req.TenantID, req.Limit, req.Offset, req.Search)
	if err != nil {
		return nil, ingestwire.ToStatusError(err)
	}
	response := &ingestwire.ListDecisionsByTenantResponse{Decisions: make([]ingestwire.Decision, 0, len(decisions))}
	for i := range decisions {
		response.Decisions = append(response.Decisions, ingestwire.FromDomainDecision(&decisions[i]))
	}
	return response, nil
}

func (s *testIngestServer) HasRecentAllow(ctx context.Context, req *ingestwire.HasRecentAllowRequest) (*ingestwire.HasRecentAllowResponse, error) {
	allowed, err := s.decisionRepo.HasRecentAllow(ctx, req.TenantID, req.Ecosystem, req.Namespace, req.Name)
	if err != nil {
		return nil, ingestwire.ToStatusError(err)
	}
	return &ingestwire.HasRecentAllowResponse{Allowed: allowed}, nil
}

func (s *testIngestServer) RecordAuditEvent(ctx context.Context, req *ingestwire.RecordAuditEventRequest) (*ingestwire.RecordAuditEventResponse, error) {
	event, err := req.Event.ToDomain()
	if err != nil {
		return nil, err
	}
	if err := s.auditRecorder.Record(ctx, event); err != nil {
		return nil, ingestwire.ToStatusError(err)
	}
	return &ingestwire.RecordAuditEventResponse{Event: ingestwire.FromDomainAuditEvent(event)}, nil
}

func testRecordDecisionHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ingestwire.RecordDecisionRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testIngestGRPCService).RecordDecision(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: ingestwire.RecordDecisionMethod}
	return interceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
		return srv.(testIngestGRPCService).RecordDecision(ctx, req.(*ingestwire.RecordDecisionRequest))
	})
}

func testGetDecisionByArtifactHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ingestwire.GetDecisionByArtifactRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testIngestGRPCService).GetDecisionByArtifact(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: ingestwire.GetDecisionByArtifactMethod}
	return interceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
		return srv.(testIngestGRPCService).GetDecisionByArtifact(ctx, req.(*ingestwire.GetDecisionByArtifactRequest))
	})
}

func testListDecisionsByTenantHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ingestwire.ListDecisionsByTenantRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testIngestGRPCService).ListDecisionsByTenant(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: ingestwire.ListDecisionsByTenantMethod}
	return interceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
		return srv.(testIngestGRPCService).ListDecisionsByTenant(ctx, req.(*ingestwire.ListDecisionsByTenantRequest))
	})
}

func testHasRecentAllowHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ingestwire.HasRecentAllowRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testIngestGRPCService).HasRecentAllow(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: ingestwire.HasRecentAllowMethod}
	return interceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
		return srv.(testIngestGRPCService).HasRecentAllow(ctx, req.(*ingestwire.HasRecentAllowRequest))
	})
}

func testRecordAuditEventHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ingestwire.RecordAuditEventRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testIngestGRPCService).RecordAuditEvent(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: ingestwire.RecordAuditEventMethod}
	return interceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
		return srv.(testIngestGRPCService).RecordAuditEvent(ctx, req.(*ingestwire.RecordAuditEventRequest))
	})
}
