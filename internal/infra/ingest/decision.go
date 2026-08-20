package ingest

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DecisionRepository adapts the proxy ingestion gRPC client to the decision repository port.
type DecisionRepository struct {
	client *GRPCClient
}

// NewDecisionRepository creates a new gRPC-backed decision repository.
func NewDecisionRepository(client *GRPCClient) *DecisionRepository {
	return &DecisionRepository{client: client}
}

// Record persists a decision through the control-plane ingestion service.
func (r *DecisionRepository) Record(ctx context.Context, decision *domain.Decision) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("recording decision: client unavailable")
	}
	return r.client.RecordDecision(ctx, decision)
}

// GetByArtifact fetches the most recent decision for an artifact.
func (r *DecisionRepository) GetByArtifact(
	ctx context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.Decision, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("getting decision by artifact: client unavailable")
	}
	return r.client.GetDecisionByArtifact(ctx, tenantID, artifact)
}

// ListByTenant lists decisions for a tenant.
func (r *DecisionRepository) ListByTenant(
	ctx context.Context,
	tenantID string,
	limit, offset int,
	search string,
) ([]domain.Decision, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("listing decisions: client unavailable")
	}
	return r.client.ListDecisionsByTenant(ctx, tenantID, limit, offset, search)
}

// HasRecentAllow checks whether an artifact has a recent allow decision.
func (r *DecisionRepository) HasRecentAllow(
	ctx context.Context,
	tenantID string,
	ecosystem domain.EcosystemType,
	namespace, name string,
) (bool, error) {
	if r == nil || r.client == nil {
		return false, fmt.Errorf("checking recent allow: client unavailable")
	}
	return r.client.HasRecentAllow(ctx, tenantID, ecosystem, namespace, name)
}

// HasRecentAllowInScope performs the has recent allow in scope operation.
func (r *DecisionRepository) HasRecentAllowInScope(
	ctx context.Context,
	scope domain.AuthorizationScope,
	ecosystem domain.EcosystemType,
	namespace, name string,
) (bool, error) {
	if r == nil || r.client == nil {
		return false, fmt.Errorf("checking scoped recent allow: client unavailable")
	}
	return r.client.HasRecentAllowInScope(ctx, scope, ecosystem, namespace, name)
}
