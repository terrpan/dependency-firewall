package ingestgrpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// RecordDecision invokes the remote ingestion service and returns the persisted decision.
func RecordDecision(ctx context.Context, conn grpc.ClientConnInterface, decision *domain.Decision) (*domain.Decision, error) {
	if decision == nil {
		return nil, fmt.Errorf("decision is required")
	}
	response := &RecordDecisionResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/RecordDecision", &RecordDecisionRequest{Decision: fromDomainDecision(decision)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	return response.Decision.toDomain()
}

// GetDecisionByArtifact invokes the remote ingestion service for one artifact decision.
func GetDecisionByArtifact(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	response := &GetDecisionByArtifactResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/GetDecisionByArtifact", &GetDecisionByArtifactRequest{TenantID: tenantID, Artifact: fromDomainArtifactIdentity(artifact)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	return response.Decision.toDomain()
}

// ListDecisionsByTenant invokes the remote ingestion service for tenant decisions.
func ListDecisionsByTenant(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, limit, offset int, search string) ([]domain.Decision, error) {
	response := &ListDecisionsByTenantResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/ListDecisionsByTenant", &ListDecisionsByTenantRequest{TenantID: tenantID, Limit: limit, Offset: offset, Search: search}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	decisions := make([]domain.Decision, 0, len(response.Decisions))
	for i := range response.Decisions {
		decision, err := response.Decisions[i].toDomain()
		if err != nil {
			return nil, fmt.Errorf("decoding decision: %w", err)
		}
		decisions = append(decisions, *decision)
	}
	return decisions, nil
}

// HasRecentAllow invokes the remote ingestion service for recent-allow lookup.
func HasRecentAllow(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	response := &HasRecentAllowResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/HasRecentAllow", &HasRecentAllowRequest{TenantID: tenantID, Ecosystem: ecosystem, Namespace: namespace, Name: name}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return false, mapClientError(err)
	}
	return response.Allowed, nil
}

// RecordAuditEvent invokes the remote ingestion service and returns the persisted audit event.
func RecordAuditEvent(ctx context.Context, conn grpc.ClientConnInterface, event *domain.AuditEvent) (*domain.AuditEvent, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}
	response := &RecordAuditEventResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/RecordAuditEvent", &RecordAuditEventRequest{Event: fromDomainAuditEvent(event)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	return response.Event.toDomain()
}
