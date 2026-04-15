// Package service implements core business workflows.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

const (
	mutableDecisionTTL       = 5 * time.Minute
	immutableDecisionTTL     = 1 * time.Hour
	enrichmentMetadataTTL    = 30 * time.Minute
)

// ProxyService orchestrates the full access-request evaluation pipeline.
type ProxyService struct {
	policies       port.PolicyRepository
	decisions      port.DecisionRepository
	decisionCache  port.DecisionCache
	metadataCache  port.MetadataCache
	enricher       port.Enricher
	evaluator      *policy.Evaluator
	upstreamClient port.UpstreamClient
	upstreamRepo   port.UpstreamRepository
	logger         *slog.Logger
}

// NewProxyService creates a new ProxyService.
func NewProxyService(
	policies port.PolicyRepository,
	decisions port.DecisionRepository,
	decisionCache port.DecisionCache,
	metadataCache port.MetadataCache,
	enricher port.Enricher,
	evaluator *policy.Evaluator,
	upstreamClient port.UpstreamClient,
	upstreamRepo port.UpstreamRepository,
	logger *slog.Logger,
) *ProxyService {
	return &ProxyService{
		policies:       policies,
		decisions:      decisions,
		decisionCache:  decisionCache,
		metadataCache:  metadataCache,
		enricher:       enricher,
		evaluator:      evaluator,
		upstreamClient: upstreamClient,
		upstreamRepo:   upstreamRepo,
		logger:         logger,
	}
}

// Evaluate processes an access request through the full pipeline:
// normalize -> check decision cache -> enrich (with metadata cache) -> evaluate policies -> cache decision -> record decision.
func (s *ProxyService) Evaluate(ctx context.Context, req domain.AccessRequest) (*domain.Decision, error) {
	// 1. Normalize the artifact identity.
	normalized, err := domain.NormalizeArtifactIdentity(req.Artifact)
	if err != nil {
		return nil, fmt.Errorf("normalizing artifact: %w", err)
	}
	req.Artifact = normalized

	// 1b. Resolve OCI mutable tags to digests for stable cache keys.
	wasMutableTag := false
	if req.Artifact.Ecosystem == domain.EcosystemOCI && req.Artifact.IsMutableReference() {
		wasMutableTag = true
		up, upErr := s.upstreamRepo.GetByEcosystem(ctx, req.TenantID, domain.EcosystemOCI)
		if upErr != nil {
			s.logger.Debug("no OCI upstream for tag resolution, continuing with tag",
				"error", upErr,
				"tenant_id", req.TenantID,
			)
		} else {
			digest, resolveErr := s.upstreamClient.ResolveTag(ctx, *up, req.Artifact)
			if resolveErr != nil {
				s.logger.Warn("tag resolution failed, continuing with tag",
					"error", resolveErr,
					"tenant_id", req.TenantID,
					"artifact", req.Artifact.CacheKey(),
				)
			} else {
				req.Artifact.Digest = digest
			}
		}
	}

	// 2. Check decision cache.
	cached, err := s.decisionCache.Get(ctx, req.TenantID, req.Artifact)
	if err == nil {
		now := time.Now()
		cached.CachedAt = &now
		s.logger.Debug("decision cache hit",
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
		return cached, nil
	}
	if !errors.Is(err, domain.ErrCacheMiss) {
		s.logger.Warn("decision cache error, proceeding without cache",
			"error", err,
			"tenant_id", req.TenantID,
		)
	}

	// 3. Try metadata cache.
	metadata, err := s.metadataCache.Get(ctx, req.TenantID, req.Artifact)
	if err != nil && !errors.Is(err, domain.ErrCacheMiss) {
		s.logger.Warn("metadata cache error",
			"error", err,
			"tenant_id", req.TenantID,
		)
	}

	// 4. If metadata cache miss, call enricher and cache the result.
	if metadata == nil {
		metadata, err = s.enricher.Enrich(ctx, req.Artifact)
		if err != nil {
			// Fail-open: log the error and continue with nil metadata.
			s.logger.Warn("enrichment failed, continuing with nil metadata",
				"error", err,
				"tenant_id", req.TenantID,
				"artifact", req.Artifact.CacheKey(),
			)
			metadata = nil
		}
		if metadata != nil {
			if cacheErr := s.metadataCache.Set(ctx, req.TenantID, req.Artifact, metadata, enrichmentMetadataTTL); cacheErr != nil {
				s.logger.Warn("failed to cache metadata",
					"error", cacheErr,
					"tenant_id", req.TenantID,
				)
			}
		}
	}

	// 5. Set the metadata on the access request.
	req.Metadata = metadata

	// 5b. Propagate mutable-tag flag so the block_mutable_tag condition can detect it.
	if wasMutableTag {
		if req.Metadata == nil {
			req.Metadata = &domain.ArtifactMetadata{}
		}
		req.Metadata.IsMutableTag = true
	}

	// 6. Load tenant's policies.
	policies, err := s.policies.ListByTenant(ctx, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("loading policies: %w", err)
	}

	// 7. Run policy evaluator.
	decision := s.evaluator.Evaluate(req, policies)

	// 8. Cache the decision (shorter TTL for mutable references).
	ttl := immutableDecisionTTL
	if req.Artifact.IsMutableReference() {
		ttl = mutableDecisionTTL
	}
	if cacheErr := s.decisionCache.Set(ctx, &decision, ttl); cacheErr != nil {
		s.logger.Warn("failed to cache decision",
			"error", cacheErr,
			"tenant_id", req.TenantID,
		)
	}

	// 9. Record the decision in the repository.
	if recordErr := s.decisions.Record(ctx, &decision); recordErr != nil {
		s.logger.Error("failed to record decision",
			"error", recordErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	}

	return &decision, nil
}

// HasAllowedManifest checks if there's a recent allow decision for any manifest
// in the given repository (tenant + ecosystem + namespace + name).
func (s *ProxyService) HasAllowedManifest(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (bool, error) {
	return s.decisions.HasRecentAllow(ctx, tenantID, artifact.Ecosystem, artifact.Namespace, artifact.Name)
}
