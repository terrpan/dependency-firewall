package port

import (
	"context"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DecisionCache caches evaluated decisions.
type DecisionCache interface {
	Get(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error)
	Set(ctx context.Context, decision *domain.Decision, ttl time.Duration) error
	Invalidate(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) error
}

// MetadataCache caches enrichment metadata.
type MetadataCache interface {
	Get(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error)
	Set(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity, metadata *domain.ArtifactMetadata, ttl time.Duration) error
}
