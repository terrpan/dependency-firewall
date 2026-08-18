package ingestgrpc

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// RecordDecision persists a proxy-evaluated decision.
func (s *Server) RecordDecision(ctx context.Context, req *RecordDecisionRequest) (*RecordDecisionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "decision is required")
	}
	decision, err := req.Decision.ToDomain()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid decision: %v", err)
	}
	if strings.TrimSpace(decision.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "decision tenant_id is required")
	}
	if err := s.service.RecordDecision(ctx, decision); err != nil {
		return nil, toStatusError(err)
	}
	return &RecordDecisionResponse{Decision: fromDomainDecision(decision)}, nil
}

// GetDecisionByArtifact returns the most recent persisted decision for an artifact.
func (s *Server) GetDecisionByArtifact(
	ctx context.Context,
	req *GetDecisionByArtifactRequest,
) (*GetDecisionByArtifactResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	decision, err := s.service.GetDecisionByArtifact(ctx, req.TenantID, req.Artifact.ToDomain())
	if err != nil {
		return nil, toStatusError(err)
	}
	return &GetDecisionByArtifactResponse{Decision: fromDomainDecision(decision)}, nil
}

// ListDecisionsByTenant lists persisted decisions for a tenant.
func (s *Server) ListDecisionsByTenant(
	ctx context.Context,
	req *ListDecisionsByTenantRequest,
) (*ListDecisionsByTenantResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	decisions, err := s.service.ListDecisionsByTenant(ctx, req.TenantID, req.Limit, req.Offset, req.Search)
	if err != nil {
		return nil, toStatusError(err)
	}
	response := &ListDecisionsByTenantResponse{Decisions: make([]Decision, 0, len(decisions))}
	for i := range decisions {
		response.Decisions = append(response.Decisions, fromDomainDecision(&decisions[i]))
	}
	return response, nil
}

// HasRecentAllow reports whether an artifact has a recent allow decision.
func (s *Server) HasRecentAllow(ctx context.Context, req *HasRecentAllowRequest) (*HasRecentAllowResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	allowed, err := s.service.HasRecentAllow(ctx, req.TenantID, req.Ecosystem, req.Namespace, req.Name)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &HasRecentAllowResponse{Allowed: allowed}, nil
}

// RecordAuditEvent persists a proxy-emitted audit event.
func (s *Server) RecordAuditEvent(
	ctx context.Context,
	req *RecordAuditEventRequest,
) (*RecordAuditEventResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "event is required")
	}
	event, err := req.Event.ToDomain()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid event: %v", err)
	}
	if strings.TrimSpace(event.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "event tenant_id is required")
	}
	if err := s.service.RecordAuditEvent(ctx, event); err != nil {
		return nil, toStatusError(err)
	}
	return &RecordAuditEventResponse{Event: fromDomainAuditEvent(event)}, nil
}

// EnqueueDependencyGraphResolve enqueues an async npm dependency graph resolve request.
func (s *Server) EnqueueDependencyGraphResolve(
	ctx context.Context,
	req *EnqueueDependencyGraphResolveRequest,
) (*EnqueueDependencyGraphResolveResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	enqueued, err := s.service.EnqueueDependencyGraphResolve(ctx, domain.DependencyGraphResolveRequest{
		TenantID: req.TenantID,
		Upstream: req.Upstream.ToDomain(),
		Root:     req.Root.ToDomain(),
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return &EnqueueDependencyGraphResolveResponse{Enqueued: enqueued}, nil
}

// ClaimDependencyGraphResolve claims the next async npm dependency graph resolve job.
func (s *Server) ClaimDependencyGraphResolve(
	ctx context.Context,
	req *ClaimDependencyGraphResolveRequest,
) (*ClaimDependencyGraphResolveResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	now := time.Now().UTC()
	if strings.TrimSpace(req.Now) != "" {
		parsed, err := time.Parse(time.RFC3339Nano, req.Now)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid now: %v", err)
		}
		now = parsed
	}
	job, err := s.service.ClaimDependencyGraphResolve(ctx, req.TenantID, now)
	if err != nil {
		return nil, toStatusError(err)
	}
	if job == nil {
		return &ClaimDependencyGraphResolveResponse{}, nil
	}
	return &ClaimDependencyGraphResolveResponse{Job: wireFromDomainDependencyGraphResolveRequest(*job)}, nil
}

// CompleteDependencyGraphResolve stores a resolved npm dependency graph.
func (s *Server) CompleteDependencyGraphResolve(
	ctx context.Context,
	req *CompleteDependencyGraphResolveRequest,
) (*CompleteDependencyGraphResolveResponse, error) {
	if req == nil || strings.TrimSpace(req.Job.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if strings.TrimSpace(req.GraphHash) == "" {
		return nil, status.Error(codes.InvalidArgument, "graph_hash is required")
	}
	if err := s.service.CompleteDependencyGraphResolve(
		ctx,
		*req.Job.ToDomain(),
		req.Nodes,
		req.Edges,
		req.GraphHash,
	); err != nil {
		return nil, toStatusError(err)
	}
	return &CompleteDependencyGraphResolveResponse{}, nil
}

// FailDependencyGraphResolve records a resolver failure and retry time.
func (s *Server) FailDependencyGraphResolve(
	ctx context.Context,
	req *FailDependencyGraphResolveRequest,
) (*FailDependencyGraphResolveResponse, error) {
	if req == nil || strings.TrimSpace(req.Job.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	retryAfter, err := time.Parse(time.RFC3339Nano, req.RetryAfter)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid retry_after: %v", err)
	}
	if err := s.service.FailDependencyGraphResolve(ctx, *req.Job.ToDomain(), req.Message, retryAfter); err != nil {
		return nil, toStatusError(err)
	}
	return &FailDependencyGraphResolveResponse{}, nil
}

// LookupDependencyGraphContext returns the graph context summary for a tenant artifact.
func (s *Server) LookupDependencyGraphContext(
	ctx context.Context,
	req *LookupDependencyGraphContextRequest,
) (*LookupDependencyGraphContextResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	dependencyContext, err := s.service.LookupDependencyGraphContext(ctx, domain.DependencyContextSummaryKey{
		TenantID:   req.TenantID,
		UpstreamID: req.UpstreamID,
		Artifact:   req.Artifact.ToDomain(),
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return &LookupDependencyGraphContextResponse{Context: dependencyContext}, nil
}

// WatchDependencyGraphResolve streams wake-up events for queued dependency graph jobs.
func (s *Server) WatchDependencyGraphResolve(
	ctx context.Context,
	req *WatchDependencyGraphResolveRequest,
) (<-chan struct{}, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	notifications, err := s.service.WatchDependencyGraphResolve(ctx, req.TenantID)
	if err != nil {
		return nil, status.Error(codes.Unimplemented, "dependency graph job notifications are unavailable")
	}
	return notifications, nil
}

func wireFromDomainDependencyGraphResolveRequest(
	req domain.DependencyGraphResolveRequest,
) *EnqueueDependencyGraphResolveRequest {
	return &EnqueueDependencyGraphResolveRequest{
		TenantID: req.TenantID,
		Upstream: fromDomainUpstream(req.Upstream),
		Root:     fromDomainArtifactIdentity(req.Root),
	}
}
