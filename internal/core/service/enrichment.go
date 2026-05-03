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
	audit         *AuditService
	defaultTTL    time.Duration
}

// NewEnrichmentService creates an EnrichmentService with the given enricher and cache.
func NewEnrichmentService(
	enricher port.Enricher,
	cache port.MetadataCache,
	logger *slog.Logger,
	audits ...*AuditService,
) *EnrichmentService {
	var audit *AuditService
	if len(audits) > 0 {
		audit = audits[0]
	}
	return &EnrichmentService{
		enricher:      enricher,
		metadataCache: cache,
		logger:        logger,
		audit:         audit,
		defaultTTL:    mutableRefTTL,
	}
}

// Enrich retrieves metadata for an artifact, using cache when available.
// On enrichment failure it returns nil metadata and no error (fail-open).
func (s *EnrichmentService) Enrich(
	ctx context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.ArtifactMetadata, error) {
	return s.EnrichWithCorrelation(ctx, tenantID, "", artifact)
}

// EnrichWithCorrelation retrieves metadata for an artifact and attaches a request correlation ID.
func (s *EnrichmentService) EnrichWithCorrelation(
	ctx context.Context,
	tenantID, correlationID string,
	artifact domain.ArtifactIdentity,
) (*domain.ArtifactMetadata, error) {
	cached, err := s.metadataCache.Get(ctx, tenantID, artifact)
	if err == nil && cached != nil {
		if auditErr := s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      tenantID,
			CorrelationID: correlationID,
			EventType:     domain.AuditEventMetadataCacheHit,
			Source:        "core/enrichment",
			Artifact:      artifact,
			Message:       "metadata cache hit",
		}); auditErr != nil {
			return nil, auditErr
		}
		s.logger.DebugContext(ctx, "metadata cache hit",
			slog.String("tenant_id", tenantID),
			slog.String("name", artifact.Name),
		)
		return cached, nil
	}
	if auditErr := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      tenantID,
		CorrelationID: correlationID,
		EventType:     domain.AuditEventMetadataCacheMiss,
		Source:        "core/enrichment",
		Artifact:      artifact,
		Message:       "metadata cache miss",
	}); auditErr != nil {
		return nil, auditErr
	}

	metadata, err := s.enricher.Enrich(ctx, artifact)
	if err != nil {
		if auditErr := s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      tenantID,
			CorrelationID: correlationID,
			EventType:     domain.AuditEventEnrichmentFailed,
			Source:        "core/enrichment",
			Artifact:      artifact,
			Message:       "artifact enrichment failed",
			Payload: map[string]any{
				"error": err.Error(),
			},
		}); auditErr != nil {
			return nil, auditErr
		}
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

func (s *EnrichmentService) recordAudit(ctx context.Context, event domain.AuditEvent) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Record(ctx, event)
}

// cacheTTL returns the appropriate TTL based on whether the artifact reference
// is mutable (tag) or immutable (digest).
func (s *EnrichmentService) cacheTTL(artifact domain.ArtifactIdentity) time.Duration {
	if artifact.Digest != "" {
		return immutableRefTTL
	}
	return mutableRefTTL
}
