package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/delivery/ingestgrpc"
)

// GRPCClient calls the control-plane proxy ingestion service over gRPC.
type GRPCClient struct {
	conn *grpc.ClientConn
}

// NewGRPCClient creates a new GRPCClient.
func NewGRPCClient(ctx context.Context, address string) (*GRPCClient, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		dialCtx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	)
	if err != nil {
		return nil, fmt.Errorf("dialing proxy ingestion service: %w", err)
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

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}
