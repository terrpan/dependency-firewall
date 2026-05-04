package ingest

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/delivery/ingestgrpc"
	"github.com/danielterry/dependency-firewall/internal/infra/controlplanegrpc"
)

// GRPCClient calls the control-plane proxy ingestion service over gRPC.
type GRPCClient struct {
	conn *grpc.ClientConn
}

// NewGRPCClient creates a new GRPCClient.
func NewGRPCClient(_ context.Context, address string) (*GRPCClient, error) {
	conn, err := controlplanegrpc.NewClientConn(address)
	if err != nil {
		return nil, fmt.Errorf("creating proxy ingestion client: %w", err)
	}

	return &GRPCClient{conn: conn}, nil
}

// Close closes the underlying client connection.
func (c *GRPCClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// RecordDecision persists one decision through the control-plane ingestion service.
func (c *GRPCClient) RecordDecision(ctx context.Context, decision *domain.Decision) error {
	persisted, err := ingestgrpc.RecordDecision(ctx, c.conn, decision)
	if err != nil {
		return err
	}
	*decision = *persisted
	return nil
}

// GetDecisionByArtifact fetches the most recent persisted decision for an artifact.
func (c *GRPCClient) GetDecisionByArtifact(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	return ingestgrpc.GetDecisionByArtifact(ctx, c.conn, tenantID, artifact)
}

// ListDecisionsByTenant fetches persisted decisions for a tenant.
func (c *GRPCClient) ListDecisionsByTenant(ctx context.Context, tenantID string, limit, offset int, search string) ([]domain.Decision, error) {
	return ingestgrpc.ListDecisionsByTenant(ctx, c.conn, tenantID, limit, offset, search)
}

// HasRecentAllow checks whether an artifact has a recent allow decision.
func (c *GRPCClient) HasRecentAllow(ctx context.Context, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	return ingestgrpc.HasRecentAllow(ctx, c.conn, tenantID, ecosystem, namespace, name)
}

// RecordAuditEvent persists one audit event through the control-plane ingestion service.
func (c *GRPCClient) RecordAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	persisted, err := ingestgrpc.RecordAuditEvent(ctx, c.conn, event)
	if err != nil {
		return err
	}
	*event = *persisted
	return nil
}
