package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"go.opentelemetry.io/otel/attribute"
)

func (s *AccessService) enrichArtifact(ctx context.Context, req domain.AccessRequest) (*domain.ArtifactMetadata, error) {
	if err := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventEnrichmentStarted,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "artifact enrichment started",
	}); err != nil {
		return nil, err
	}

	enrichCtx, enrichSpan := tracer.Start(ctx, "access.enrich_artifact")
	metadata, err := s.enrichment.EnrichWithCorrelation(enrichCtx, req.TenantID, req.RequestID, req.Artifact)
	if err != nil {
		recordSpanError(enrichSpan, err)
		enrichSpan.End()
		_ = s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventError,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			Artifact:      req.Artifact,
			Message:       "artifact enrichment failed",
			Payload: map[string]any{
				"stage": "enrichment",
				"error": err.Error(),
			},
		})
		return nil, fmt.Errorf("enriching artifact: %w", err)
	}
	enrichSpan.SetAttributes(attribute.Bool("metadata.available", metadata != nil))
	enrichSpan.End()

	return metadata, nil
}

func applyMutableTagMetadata(req *domain.AccessRequest, wasMutableTag bool) {
	if !wasMutableTag {
		return
	}
	if req.Metadata == nil {
		req.Metadata = &domain.ArtifactMetadata{}
	}
	req.Metadata.IsMutableTag = true
}
