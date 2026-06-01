// Package service implements core business workflows for the dependency firewall.
package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"go.opentelemetry.io/otel/attribute"
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
	ctx, span := serviceTracer().Start(ctx, "enrichment.fetch_metadata")
	span.SetAttributes(
		attribute.String("tenant.id", tenantID),
		attribute.String("artifact.ecosystem", string(artifact.Ecosystem)),
		attribute.String("artifact.reference_type", artifactReferenceType(artifact)),
	)
	if correlationID != "" {
		span.SetAttributes(attribute.String("request.id", correlationID))
	}
	defer span.End()

	cacheCtx, cacheSpan := serviceTracer().Start(ctx, "enrichment.metadata_cache_lookup")
	cached, err := s.metadataCache.Get(cacheCtx, tenantID, artifact)
	if err != nil {
		recordSpanErrorIfUnexpected(cacheSpan, err)
		if errors.Is(err, domain.ErrCacheMiss) {
			cacheSpan.AddEvent("cache.miss")
		}
	}
	if err == nil && cached != nil {
		cacheSpan.SetAttributes(attribute.Bool("cache.hit", true))
		cacheSpan.End()
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
	cacheSpan.SetAttributes(attribute.Bool("cache.hit", false))
	cacheSpan.End()
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

	enrichCtx, enrichSpan := serviceTracer().Start(ctx, "enrichment.query_sources")
	metadata, err := s.enricher.Enrich(enrichCtx, artifact)
	if err != nil {
		recordSpanError(enrichSpan, err)
	}
	if err != nil {
		enrichSpan.AddEvent("enrichment.failed_open")
		enrichSpan.End()
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
	enrichSpan.SetAttributes(attribute.Bool("metadata.available", metadata != nil))
	enrichSpan.End()

	ttl := s.cacheTTL(artifact)
	if metadata != nil {
		writeCtx, writeSpan := serviceTracer().Start(ctx, "enrichment.metadata_cache_store")
		if cacheErr := s.metadataCache.Set(writeCtx, tenantID, artifact, metadata, ttl); cacheErr != nil {
			recordSpanError(writeSpan, cacheErr)
			s.logger.WarnContext(ctx, "failed to cache metadata",
				slog.String("tenant_id", tenantID),
				slog.String("name", artifact.Name),
				slog.String("error", cacheErr.Error()),
			)
		}
		writeSpan.SetAttributes(attribute.Int64("cache.ttl_ms", ttl.Milliseconds()))
		writeSpan.End()
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
