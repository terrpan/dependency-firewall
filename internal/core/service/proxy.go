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
	mutableDecisionTTL   = 5 * time.Minute
	immutableDecisionTTL = 1 * time.Hour
)

// AccessService orchestrates the shared access-evaluation pipeline.
type AccessService struct {
	policies       port.PolicyRepository
	decisions      port.DecisionRepository
	decisionCache  port.DecisionCache
	enrichment     *EnrichmentService
	evaluator      *policy.Evaluator
	upstreamClient port.UpstreamClient
	upstreamRepo   port.UpstreamRepository
	logger         *slog.Logger
}

// NewAccessService creates a new AccessService.
func NewAccessService(
	policies port.PolicyRepository,
	decisions port.DecisionRepository,
	decisionCache port.DecisionCache,
	enrichment *EnrichmentService,
	evaluator *policy.Evaluator,
	upstreamClient port.UpstreamClient,
	upstreamRepo port.UpstreamRepository,
	logger *slog.Logger,
) *AccessService {
	return &AccessService{
		policies:       policies,
		decisions:      decisions,
		decisionCache:  decisionCache,
		enrichment:     enrichment,
		evaluator:      evaluator,
		upstreamClient: upstreamClient,
		upstreamRepo:   upstreamRepo,
		logger:         logger,
	}
}

// Evaluate processes an access request through the full pipeline:
// normalize -> check decision cache -> enrich (with metadata cache) -> evaluate policies -> cache decision -> record decision.
func (s *AccessService) Evaluate(ctx context.Context, req domain.AccessRequest) (*domain.Decision, error) {
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
			digest, resolveErr := s.upstreamClient.ResolveReference(ctx, *up, req.Artifact)
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

	// 3. Load enrichment metadata through the dedicated enrichment workflow.
	metadata, err := s.enrichment.Enrich(ctx, req.TenantID, req.Artifact)
	if err != nil {
		return nil, fmt.Errorf("enriching artifact: %w", err)
	}

	// 4. Set the metadata on the access request.
	req.Metadata = metadata

	// 4b. Propagate mutable-tag flag so the block_mutable_tag condition can detect it.
	if wasMutableTag {
		if req.Metadata == nil {
			req.Metadata = &domain.ArtifactMetadata{}
		}
		req.Metadata.IsMutableTag = true
	}

	// 5. Load tenant's policies.
	policies, err := s.policies.ListByTenant(ctx, req.TenantID)
	if err != nil {
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			return s.denyForInvalidPolicySet(ctx, req, err), nil
		}
		return nil, fmt.Errorf("loading policies: %w", err)
	}
	if err := policy.ValidatePolicies(policies); err != nil {
		return s.denyForInvalidPolicySet(ctx, req, err), nil
	}
	policyHash, err := policy.HashPolicies(policies)
	if err != nil {
		return s.denyForInvalidPolicySet(ctx, req, err), nil
	}

	// 6. Run policy evaluator.
	decision := s.evaluator.Evaluate(req, policies)
	decision.PolicyHash = policyHash

	// 7. Cache the decision (shorter TTL for mutable references).
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

	// 8. Record the decision in the repository.
	if recordErr := s.decisions.Record(ctx, &decision); recordErr != nil {
		s.logger.Error("failed to record decision",
			"error", recordErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	}

	return &decision, nil
}

// HasRecentAllow checks if there's a recent allow decision for the given
// repository identity (tenant + ecosystem + namespace + name).
func (s *AccessService) HasRecentAllow(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (bool, error) {
	return s.decisions.HasRecentAllow(ctx, tenantID, artifact.Ecosystem, artifact.Namespace, artifact.Name)
}

func (s *AccessService) denyForInvalidPolicySet(ctx context.Context, req domain.AccessRequest, validationErr error) *domain.Decision {
	s.logger.Error("invalid policy set, denying request",
		"error", validationErr,
		"tenant_id", req.TenantID,
		"artifact", req.Artifact.CacheKey(),
	)

	decision := domain.Decision{
		TenantID: req.TenantID,
		Artifact: req.Artifact,
		Outcome:  domain.DecisionDeny,
		Reason:   "invalid policy configuration",
		Reasons: []domain.EvaluationReason{
			{
				Category: domain.ReasonCategoryEvaluationError,
				Action:   domain.PolicyActionDeny,
				Message:  validationErr.Error(),
			},
		},
		EvaluatedAt: time.Now(),
	}

	ttl := immutableDecisionTTL
	if req.Artifact.IsMutableReference() {
		ttl = mutableDecisionTTL
	}
	if cacheErr := s.decisionCache.Set(ctx, &decision, ttl); cacheErr != nil {
		s.logger.Warn("failed to cache invalid-policy decision",
			"error", cacheErr,
			"tenant_id", req.TenantID,
		)
	}
	if recordErr := s.decisions.Record(ctx, &decision); recordErr != nil {
		s.logger.Error("failed to record invalid-policy decision",
			"error", recordErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	}

	return &decision
}
