// Package ingestgrpc exposes proxy ingestion services over gRPC.
package ingestgrpc

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	wire "github.com/danielterry/dependency-firewall/internal/wire/ingestgrpc"
)

const serviceName = wire.ServiceName

type proxyIngestService interface {
	RecordDecision(context.Context, *domain.Decision) error
	GetDecisionByArtifact(context.Context, string, domain.ArtifactIdentity) (*domain.Decision, error)
	ListDecisionsByTenant(context.Context, string, int, int, string) ([]domain.Decision, error)
	HasRecentAllow(context.Context, string, domain.EcosystemType, string, string) (bool, error)
	RecordAuditEvent(context.Context, *domain.AuditEvent) error
	EnqueueDependencyGraphResolve(context.Context, domain.DependencyGraphResolveRequest) (bool, error)
	ClaimDependencyGraphResolve(context.Context, time.Time) (*domain.DependencyGraphResolveRequest, error)
	CompleteDependencyGraphResolve(context.Context, domain.DependencyGraphResolveRequest, []domain.DependencyGraphNode, []domain.DependencyGraphEdge, string) error
	FailDependencyGraphResolve(context.Context, domain.DependencyGraphResolveRequest, string, time.Time) error
	WatchDependencyGraphResolve(context.Context) (<-chan struct{}, error)
	LookupDependencyGraphContext(context.Context, domain.DependencyContextSummaryKey) (*domain.DependencyContext, error)
}

type proxyIngestGRPCService interface {
	RecordDecision(context.Context, *RecordDecisionRequest) (*RecordDecisionResponse, error)
	GetDecisionByArtifact(context.Context, *GetDecisionByArtifactRequest) (*GetDecisionByArtifactResponse, error)
	ListDecisionsByTenant(context.Context, *ListDecisionsByTenantRequest) (*ListDecisionsByTenantResponse, error)
	HasRecentAllow(context.Context, *HasRecentAllowRequest) (*HasRecentAllowResponse, error)
	RecordAuditEvent(context.Context, *RecordAuditEventRequest) (*RecordAuditEventResponse, error)
	EnqueueDependencyGraphResolve(context.Context, *EnqueueDependencyGraphResolveRequest) (*EnqueueDependencyGraphResolveResponse, error)
	ClaimDependencyGraphResolve(context.Context, *ClaimDependencyGraphResolveRequest) (*ClaimDependencyGraphResolveResponse, error)
	CompleteDependencyGraphResolve(context.Context, *CompleteDependencyGraphResolveRequest) (*CompleteDependencyGraphResolveResponse, error)
	FailDependencyGraphResolve(context.Context, *FailDependencyGraphResolveRequest) (*FailDependencyGraphResolveResponse, error)
	WatchDependencyGraphResolve(context.Context) (<-chan struct{}, error)
	LookupDependencyGraphContext(context.Context, *LookupDependencyGraphContextRequest) (*LookupDependencyGraphContextResponse, error)
}

// Server serves proxy ingestion RPCs over gRPC.
type Server struct {
	service proxyIngestService
}

// TenantIDFromRequest returns the tenant id carried by ingest gRPC requests.
func TenantIDFromRequest(req any) string {
	return wire.TenantIDFromRequest(req)
}

// NewServer creates a new Server.
func NewServer(service proxyIngestService) *Server {
	return &Server{service: service}
}

// Register registers the ingestion service on the given gRPC registrar.
func (s *Server) Register(registrar grpc.ServiceRegistrar) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*proxyIngestGRPCService)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "RecordDecision", Handler: s.recordDecisionHandler},
			{MethodName: "GetDecisionByArtifact", Handler: s.getDecisionByArtifactHandler},
			{MethodName: "ListDecisionsByTenant", Handler: s.listDecisionsByTenantHandler},
			{MethodName: "HasRecentAllow", Handler: s.hasRecentAllowHandler},
			{MethodName: "RecordAuditEvent", Handler: s.recordAuditEventHandler},
			{MethodName: "EnqueueDependencyGraphResolve", Handler: s.enqueueDependencyGraphResolveHandler},
			{MethodName: "ClaimDependencyGraphResolve", Handler: s.claimDependencyGraphResolveHandler},
			{MethodName: "CompleteDependencyGraphResolve", Handler: s.completeDependencyGraphResolveHandler},
			{MethodName: "FailDependencyGraphResolve", Handler: s.failDependencyGraphResolveHandler},
			{MethodName: "LookupDependencyGraphContext", Handler: s.lookupDependencyGraphContextHandler},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "WatchDependencyGraphResolve",
				Handler:       s.watchDependencyGraphResolveHandler,
				ServerStreams: true,
			},
		},
	}, s)
}
