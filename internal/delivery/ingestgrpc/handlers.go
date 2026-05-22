package ingestgrpc

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
func (s *Server) GetDecisionByArtifact(ctx context.Context, req *GetDecisionByArtifactRequest) (*GetDecisionByArtifactResponse, error) {
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
func (s *Server) ListDecisionsByTenant(ctx context.Context, req *ListDecisionsByTenantRequest) (*ListDecisionsByTenantResponse, error) {
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
func (s *Server) RecordAuditEvent(ctx context.Context, req *RecordAuditEventRequest) (*RecordAuditEventResponse, error) {
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
