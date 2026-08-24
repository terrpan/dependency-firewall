package ingest

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/infra/controlplanegrpc"
	ingestwire "github.com/danielterry/dependency-firewall/internal/wire/ingestgrpc"
)

// GRPCClient calls the control-plane proxy ingestion service over gRPC.
type GRPCClient struct {
	conn *grpc.ClientConn
}

// NewGRPCClient creates a new GRPCClient.
func NewGRPCClient(_ context.Context, address string, configs ...config.BundleTLSConfig) (*GRPCClient, error) {
	conn, err := controlplanegrpc.NewClientConn(address, configs...)
	if err != nil {
		return nil, fmt.Errorf("creating proxy ingestion client: %w", err)
	}

	return &GRPCClient{conn: conn}, nil
}

// NewGRPCClientWithDialOptions creates an ingest client from process-local transport credentials.
func NewGRPCClientWithDialOptions(address string, options ...grpc.DialOption) (*GRPCClient, error) {
	conn, err := grpc.NewClient(address, options...)
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
	persisted, err := ingestwire.RecordDecision(ctx, c.conn, decision)
	if err != nil {
		return err
	}
	*decision = *persisted
	return nil
}

// GetDecisionByArtifact fetches the most recent persisted decision for an artifact.
func (c *GRPCClient) GetDecisionByArtifact(
	ctx context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.Decision, error) {
	return ingestwire.GetDecisionByArtifact(ctx, c.conn, tenantID, artifact)
}

// ListDecisionsByTenant fetches persisted decisions for a tenant.
func (c *GRPCClient) ListDecisionsByTenant(
	ctx context.Context,
	tenantID string,
	limit, offset int,
	search string,
) ([]domain.Decision, error) {
	return ingestwire.ListDecisionsByTenant(ctx, c.conn, tenantID, limit, offset, search)
}

// HasRecentAllow checks whether an artifact has a recent allow decision.
func (c *GRPCClient) HasRecentAllow(
	ctx context.Context,
	tenantID string,
	ecosystem domain.EcosystemType,
	namespace, name string,
) (bool, error) {
	return ingestwire.HasRecentAllow(ctx, c.conn, tenantID, ecosystem, namespace, name)
}

// RecordAuditEvent persists one audit event through the control-plane ingestion service.
func (c *GRPCClient) RecordAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	persisted, err := ingestwire.RecordAuditEvent(ctx, c.conn, event)
	if err != nil {
		return err
	}
	*event = *persisted
	return nil
}

// EnqueueDependencyGraphResolve enqueues one dependency graph resolve request.
func (c *GRPCClient) EnqueueDependencyGraphResolve(
	ctx context.Context,
	req domain.DependencyGraphResolveRequest,
) (bool, error) {
	return ingestwire.EnqueueDependencyGraphResolve(ctx, c.conn, req)
}

// ClaimNextResolveJob claims the next dependency graph resolver job through the control plane.
func (c *GRPCClient) ClaimNextResolveJob(
	ctx context.Context,
	tenantID string,
	now time.Time,
) (*domain.DependencyGraphResolveRequest, error) {
	return ingestwire.ClaimDependencyGraphResolve(ctx, c.conn, tenantID, now)
}

// CompleteResolve persists a completed dependency graph through the control plane.
func (c *GRPCClient) CompleteResolve(
	ctx context.Context,
	req domain.DependencyGraphResolveRequest,
	nodes []domain.DependencyGraphNode,
	edges []domain.DependencyGraphEdge,
	graphHash string,
) error {
	return ingestwire.CompleteDependencyGraphResolve(ctx, c.conn, req, nodes, edges, graphHash)
}

// FailResolve persists a dependency graph resolver failure through the control plane.
func (c *GRPCClient) FailResolve(
	ctx context.Context,
	req domain.DependencyGraphResolveRequest,
	message string,
	retryAfter time.Time,
) error {
	return ingestwire.FailDependencyGraphResolve(ctx, c.conn, req, message, retryAfter)
}

// LookupContext loads the dependency graph context summary for an artifact through the control plane.
func (c *GRPCClient) LookupContext(
	ctx context.Context,
	key domain.DependencyContextSummaryKey,
) (*domain.DependencyContext, error) {
	return ingestwire.LookupDependencyGraphContext(ctx, c.conn, key)
}

const watchResolveJobsReconnectDelay = 5 * time.Second

// WatchResolveJobs streams wake-up signals for queued dependency graph jobs,
// reconnecting until ctx is canceled. The returned channel is closed when ctx ends.
func (c *GRPCClient) WatchResolveJobs(ctx context.Context, tenantID string) <-chan struct{} {
	notifications := make(chan struct{}, 1)
	go func() {
		defer close(notifications)
		for ctx.Err() == nil {
			stream, err := ingestwire.WatchDependencyGraphResolve(ctx, c.conn, tenantID)
			if err == nil {
				for stream.Recv() == nil {
					select {
					case notifications <- struct{}{}:
					default:
					}
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(watchResolveJobsReconnectDelay):
			}
		}
	}()
	return notifications
}
