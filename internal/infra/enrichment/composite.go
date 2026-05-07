// Package enrichment provides composite enrichment combining multiple sources.
package enrichment

import (
	"context"
	"log/slog"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// CompositeEnricher combines multiple enrichers into a single enrichment pipeline.
type CompositeEnricher struct {
	enrichers []port.Enricher
	logger    *slog.Logger
}

// NewCompositeEnricher creates an enricher that runs all provided enrichers and merges results.
func NewCompositeEnricher(logger *slog.Logger, enrichers ...port.Enricher) *CompositeEnricher {
	return &CompositeEnricher{
		enrichers: enrichers,
		logger:    logger,
	}
}

// Enrich runs all enrichers and merges their metadata results.
// If an enricher fails, it logs the error and continues with the next enricher (fail-soft).
// Returns merged metadata from all successful enrichers.
func (c *CompositeEnricher) Enrich(ctx context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	c.logger.InfoContext(ctx, "composite enricher called",
		"artifact", artifact.CacheKey(),
		"enricher_count", len(c.enrichers),
	)
	merged := &domain.ArtifactMetadata{}

	for i, enricher := range c.enrichers {
		c.logger.InfoContext(ctx, "calling enricher",
			"index", i,
			"artifact", artifact.CacheKey(),
		)
		meta, err := enricher.Enrich(ctx, artifact)
		if err != nil {
			c.logger.WarnContext(ctx, "enricher failed, continuing with others",
				"error", err,
				"artifact", artifact.CacheKey(),
			)
			continue
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
	if len(src.Licenses) > 0 {
		dst.Licenses = append(dst.Licenses, src.Licenses...)
	}
	if len(src.Vulnerabilities) > 0 {
		dst.Vulnerabilities = append(dst.Vulnerabilities, src.Vulnerabilities...)
	}
	if src.IsMutableTag {
		dst.IsMutableTag = true
	}
	if src.SourceRepository != nil {
		copyRepo := *src.SourceRepository
		dst.SourceRepository = &copyRepo
	}
	if src.Scorecard != nil {
		copyScorecard := &domain.ScorecardResult{
			UnavailableReason: src.Scorecard.UnavailableReason,
		}
		if src.Scorecard.Score != nil {
			score := *src.Scorecard.Score
			copyScorecard.Score = &score
		}
		if len(src.Scorecard.Checks) > 0 {
			copyScorecard.Checks = make(map[string]float64, len(src.Scorecard.Checks))
			for name, score := range src.Scorecard.Checks {
				copyScorecard.Checks[name] = score
			}
		}
		dst.Scorecard = copyScorecard
	}
}
