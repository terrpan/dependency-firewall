package ingestgrpc

import (
	"context"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	wire "github.com/danielterry/dependency-firewall/internal/wire/ingestgrpc"
)

// RecordDecision invokes the remote ingestion service and returns the persisted decision.
func RecordDecision(ctx context.Context, conn grpc.ClientConnInterface, decision *domain.Decision) (*domain.Decision, error) {
	return wire.RecordDecision(ctx, conn, decision)
}

// GetDecisionByArtifact invokes the remote ingestion service for one artifact decision.
func GetDecisionByArtifact(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	return wire.GetDecisionByArtifact(ctx, conn, tenantID, artifact)
}

// ListDecisionsByTenant invokes the remote ingestion service for tenant decisions.
func ListDecisionsByTenant(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, limit, offset int, search string) ([]domain.Decision, error) {
	return wire.ListDecisionsByTenant(ctx, conn, tenantID, limit, offset, search)
}

// HasRecentAllow invokes the remote ingestion service for recent-allow lookup.
func HasRecentAllow(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	return wire.HasRecentAllow(ctx, conn, tenantID, ecosystem, namespace, name)
}

// RecordAuditEvent invokes the remote ingestion service and returns the persisted audit event.
func RecordAuditEvent(ctx context.Context, conn grpc.ClientConnInterface, event *domain.AuditEvent) (*domain.AuditEvent, error) {
	return wire.RecordAuditEvent(ctx, conn, event)
}
