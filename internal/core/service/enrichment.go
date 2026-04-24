// Package service implements core business workflows for the dependency firewall.
package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

const (
	mutableRefTTL   = 1 * time.Hour
	immutableRefTTL = 24 * time.Hour
)

// EnrichmentService orchestrates artifact enrichment with caching.
type EnrichmentService struct {
	enricher      port.Enricher
	metadataCache port.MetadataCache
	logger        *slog.Logger
	defaultTTL    time.Duration
}

// NewEnrichmentService creates an EnrichmentService with the given enricher and cache.
func NewEnrichmentService(
	enricher port.Enricher,
	cache port.MetadataCache,
	logger *slog.Logger,
) *EnrichmentService {
	return &EnrichmentService{
		enricher:      enricher,
		metadataCache: cache,
		logger:        logger,
		defaultTTL:    mutableRefTTL,
	}
}

// Enrich retrieves metadata for an artifact, using cache when available.
// On enrichment failure it returns nil metadata and no error (fail-open).
func (s *EnrichmentService) Enrich(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	cached, err := s.metadataCache.Get(ctx, tenantID, artifact)
	if err == nil && cached != nil {
		s.logger.DebugContext(ctx, "metadata cache hit",
			slog.String("tenant_id", tenantID),
			slog.String("name", artifact.Name),
		)
		return cached, nil
	}

	metadata, err := s.enricher.Enrich(ctx, artifact)
	if err != nil {
		s.logger.WarnContext(ctx, "enrichment failed, proceeding without metadata",
			slog.String("tenant_id", tenantID),
			slog.String("name", artifact.Name),
			slog.String("error", err.Error()),
		)
		return nil, nil
	}

	ttl := s.cacheTTL(artifact)
	if metadata != nil {
		if cacheErr := s.metadataCache.Set(ctx, tenantID, artifact, metadata, ttl); cacheErr != nil {
			s.logger.WarnContext(ctx, "failed to cache metadata",
				slog.String("tenant_id", tenantID),
				slog.String("name", artifact.Name),
				slog.String("error", cacheErr.Error()),
			)
		}
	}

	return metadata, nil
}

// cacheTTL returns the appropriate TTL based on whether the artifact reference
// is mutable (tag) or immutable (digest).
func (s *EnrichmentService) cacheTTL(artifact domain.ArtifactIdentity) time.Duration {
	if artifact.Digest != "" {
		return immutableRefTTL
	}
	return mutableRefTTL
}
