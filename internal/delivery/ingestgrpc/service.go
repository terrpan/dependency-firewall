// Package ingestgrpc exposes proxy ingestion services over gRPC.
package ingestgrpc

import (
	"context"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const serviceName = "dependencyfirewall.proxyingest.v1.ProxyIngestService"

type proxyIngestService interface {
	RecordDecision(context.Context, *domain.Decision) error
	GetDecisionByArtifact(context.Context, string, domain.ArtifactIdentity) (*domain.Decision, error)
	ListDecisionsByTenant(context.Context, string, int, int, string) ([]domain.Decision, error)
	HasRecentAllow(context.Context, string, domain.EcosystemType, string, string) (bool, error)
	RecordAuditEvent(context.Context, *domain.AuditEvent) error
}

type proxyIngestGRPCService interface {
	RecordDecision(context.Context, *RecordDecisionRequest) (*RecordDecisionResponse, error)
	GetDecisionByArtifact(context.Context, *GetDecisionByArtifactRequest) (*GetDecisionByArtifactResponse, error)
	ListDecisionsByTenant(context.Context, *ListDecisionsByTenantRequest) (*ListDecisionsByTenantResponse, error)
	HasRecentAllow(context.Context, *HasRecentAllowRequest) (*HasRecentAllowResponse, error)
	RecordAuditEvent(context.Context, *RecordAuditEventRequest) (*RecordAuditEventResponse, error)
}

// Server serves proxy ingestion RPCs over gRPC.
type Server struct {
	service proxyIngestService
}

// TenantIDFromRequest returns the tenant id carried by ingest gRPC requests.
func TenantIDFromRequest(req any) string {
	switch typed := req.(type) {
	case *RecordDecisionRequest:
		return typed.Decision.TenantID
	case *GetDecisionByArtifactRequest:
		return typed.TenantID
	case *ListDecisionsByTenantRequest:
		return typed.TenantID
	case *HasRecentAllowRequest:
		return typed.TenantID
	case *RecordAuditEventRequest:
		return typed.Event.TenantID
	default:
		return ""
	}
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
		},
	}, s)
}
