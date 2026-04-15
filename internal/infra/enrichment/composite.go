// Package enrichment provides composite enrichment combining multiple sources.
package enrichment

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// CompositeEnricher combines multiple enrichers into a single enrichment pipeline.
type CompositeEnricher struct {
	enrichers []port.Enricher
}

// NewCompositeEnricher creates an enricher that runs all provided enrichers and merges results.
func NewCompositeEnricher(enrichers ...port.Enricher) *CompositeEnricher {
	return &CompositeEnricher{
		enrichers: enrichers,
	}
}

// Enrich runs all enrichers and merges their metadata results.
// If any enricher fails, the error is returned and enrichment stops.
// If all enrichers succeed, their metadata is merged (non-nil fields take precedence in order).
func (c *CompositeEnricher) Enrich(ctx context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	merged := &domain.ArtifactMetadata{}

	for _, enricher := range c.enrichers {
		meta, err := enricher.Enrich(ctx, artifact)
		if err != nil {
			return nil, err
		}
		if meta != nil {
			mergeMetadata(merged, meta)
		}
	}

	return merged, nil
}

// mergeMetadata merges src into dst, with src taking precedence for non-nil/non-zero fields.
func mergeMetadata(dst, src *domain.ArtifactMetadata) {
	if src.PublishedAt != nil {
		dst.PublishedAt = src.PublishedAt
	}
	if src.MaxCVSS != nil {
		dst.MaxCVSS = src.MaxCVSS
	}
	if len(src.Vulnerabilities) > 0 {
		dst.Vulnerabilities = append(dst.Vulnerabilities, src.Vulnerabilities...)
	}
	if src.IsMutableTag {
		dst.IsMutableTag = true
	}
}
