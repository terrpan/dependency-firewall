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
	audit          *AuditService
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
	audits ...*AuditService,
) *AccessService {
	var audit *AuditService
	if len(audits) > 0 {
		audit = audits[0]
	}
	return &AccessService{
		policies:       policies,
		decisions:      decisions,
		decisionCache:  decisionCache,
		enrichment:     enrichment,
		evaluator:      evaluator,
		upstreamClient: upstreamClient,
		upstreamRepo:   upstreamRepo,
		logger:         logger,
		audit:          audit,
	}
}

// Evaluate processes an access request through the full pipeline:
// normalize -> check decision cache -> enrich (with metadata cache) -> evaluate policies -> cache decision -> record decision.
func (s *AccessService) Evaluate(ctx context.Context, req domain.AccessRequest) (*domain.Decision, error) {
	if err := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventEvaluationStarted,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "evaluation started",
	}); err != nil {
		return nil, err
	}

	// 1. Normalize the artifact identity.
	originalArtifact := req.Artifact
	normalized, err := domain.NormalizeArtifactIdentity(req.Artifact)
	if err != nil {
		_ = s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventError,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			Artifact:      req.Artifact,
			Message:       "artifact normalization failed",
			Payload: map[string]any{
				"stage": "normalize_artifact",
				"error": err.Error(),
			},
		})
		return nil, fmt.Errorf("normalizing artifact: %w", err)
	}
	req.Artifact = normalized
	if err := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventArtifactNormalized,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "artifact normalized",
		Payload: map[string]any{
			"original_artifact": originalArtifact,
		},
	}); err != nil {
		return nil, err
	}

	// 1b. Resolve OCI mutable tags to digests for stable cache keys.
	wasMutableTag := false
	if req.Artifact.Ecosystem == domain.EcosystemOCI && req.Artifact.IsMutableReference() {
		wasMutableTag = true
		upstream := req.Upstream
		if upstream.ID == "" {
			up, upErr := s.upstreamRepo.GetByEcosystem(ctx, req.TenantID, domain.EcosystemOCI)
			if upErr != nil {
				s.logger.Debug("no OCI upstream for tag resolution, continuing with tag",
					"error", upErr,
					"tenant_id", req.TenantID,
				)
			} else {
				upstream = *up
			}
		}
		if upstream.ID == "" {
			s.logger.Debug("no OCI upstream for tag resolution, continuing with tag",
				"tenant_id", req.TenantID,
			)
		} else {
			digest, resolveErr := s.upstreamClient.ResolveReference(ctx, upstream, req.Artifact)
			if resolveErr != nil {
				_ = s.recordAudit(ctx, domain.AuditEvent{
					TenantID:      req.TenantID,
					CorrelationID: req.RequestID,
					EventType:     domain.AuditEventError,
					Source:        "core/access",
					UpstreamID:    upstream.ID,
					Artifact:      req.Artifact,
					Message:       "reference resolution failed",
					Payload: map[string]any{
						"stage": "resolve_reference",
						"error": resolveErr.Error(),
					},
				})
				s.logger.Warn("tag resolution failed, continuing with tag",
					"error", resolveErr,
					"tenant_id", req.TenantID,
					"artifact", req.Artifact.CacheKey(),
				)
			} else {
				req.Artifact.Digest = digest
				if err := s.recordAudit(ctx, domain.AuditEvent{
					TenantID:      req.TenantID,
					CorrelationID: req.RequestID,
					EventType:     domain.AuditEventReferenceResolved,
					Source:        "core/access",
					UpstreamID:    upstream.ID,
					Artifact:      req.Artifact,
					Message:       "mutable OCI reference resolved to digest",
					Payload: map[string]any{
						"resolved_digest": digest,
					},
				}); err != nil {
					return nil, err
				}
			}
		}
	}

	// 2. Check decision cache.
	cached, err := s.decisionCache.Get(ctx, req.TenantID, req.Artifact)
	if err == nil {
		now := time.Now()
		cached.CachedAt = &now
		if auditErr := s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventDecisionCacheHit,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			Artifact:      req.Artifact,
			Outcome:       cached.Outcome,
			PolicyID:      cached.PolicyID,
			Message:       "decision cache hit",
		}); auditErr != nil {
			return nil, auditErr
		}
		s.logger.Debug("decision cache hit",
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
		return cached, nil
	}
	if !errors.Is(err, domain.ErrCacheMiss) {
		_ = s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventError,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			Artifact:      req.Artifact,
			Message:       "decision cache lookup failed",
			Payload: map[string]any{
				"stage": "decision_cache_lookup",
				"error": err.Error(),
			},
		})
		s.logger.Warn("decision cache error, proceeding without cache",
			"error", err,
			"tenant_id", req.TenantID,
		)
	} else if auditErr := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventDecisionCacheMiss,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "decision cache miss",
	}); auditErr != nil {
		return nil, auditErr
	}

	// 3. Load enrichment metadata through the dedicated enrichment workflow.
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
	metadata, err := s.enrichment.EnrichWithCorrelation(ctx, req.TenantID, req.RequestID, req.Artifact)
	if err != nil {
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
		_ = s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventError,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			Artifact:      req.Artifact,
			Message:       "policy load failed",
			Payload: map[string]any{
				"stage": "load_policies",
				"error": err.Error(),
			},
		})
		return nil, fmt.Errorf("loading policies: %w", err)
	}
	if err := policy.ValidatePolicies(policies); err != nil {
		return s.denyForInvalidPolicySet(ctx, req, err), nil
	}
	effectivePolicies := filterPoliciesForUpstream(policies, req.Upstream.ID)
	policyHash, err := policy.HashPolicies(effectivePolicies)
	if err != nil {
		return s.denyForInvalidPolicySet(ctx, req, err), nil
	}
	if err := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventPoliciesLoaded,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "policies loaded for evaluation",
		Payload: map[string]any{
			"tenant_policy_count":    len(policies),
			"effective_policy_count": len(effectivePolicies),
			"policy_hash":            policyHash,
		},
	}); err != nil {
		return nil, err
	}

	// 6. Run policy evaluator.
	decision := s.evaluator.Evaluate(req, effectivePolicies)
	decision.PolicyHash = policyHash
	for _, reason := range decision.Reasons {
		if err := s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventPolicyMatched,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			PolicyID:      reason.PolicyID,
			Outcome:       decision.Outcome,
			Artifact:      req.Artifact,
			Message:       reason.Message,
			Payload: map[string]any{
				"policy_name": reason.PolicyName,
				"category":    reason.Category,
				"action":      reason.Action,
			},
		}); err != nil {
			return nil, err
		}
	}
	if err := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventDecisionComputed,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		PolicyID:      decision.PolicyID,
		Outcome:       decision.Outcome,
		Artifact:      decision.Artifact,
		Message:       "decision computed",
		Payload: map[string]any{
			"reason":             decision.Reason,
			"warnings":           decision.Warnings,
			"reason_count":       len(decision.Reasons),
			"metadata_available": metadata != nil,
			"metadata_summary":   s.metadataSummary(metadata),
		},
	}); err != nil {
		return nil, err
	}

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
		_ = s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventError,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			PolicyID:      decision.PolicyID,
			Outcome:       decision.Outcome,
			Artifact:      decision.Artifact,
			Message:       "decision persistence failed",
			Payload: map[string]any{
				"stage": "persist_decision",
				"error": recordErr.Error(),
			},
		})
		s.logger.Error("failed to record decision",
			"error", recordErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	} else if auditErr := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventDecisionPersisted,
		Source:        "core/access",
		EntityType:    "decision",
		EntityID:      decision.ID,
		UpstreamID:    req.Upstream.ID,
		PolicyID:      decision.PolicyID,
		Outcome:       decision.Outcome,
		Artifact:      decision.Artifact,
		Message:       "decision persisted",
		Payload: map[string]any{
			"policy_hash": decision.PolicyHash,
		},
	}); auditErr != nil {
		return nil, auditErr
	}

	return &decision, nil
}

// HasRecentAllow checks if there's a recent allow decision for the given
// repository identity (tenant + ecosystem + namespace + name).
func (s *AccessService) HasRecentAllow(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (bool, error) {
	return s.decisions.HasRecentAllow(ctx, tenantID, artifact.Ecosystem, artifact.Namespace, artifact.Name)
}

func (s *AccessService) denyForInvalidPolicySet(ctx context.Context, req domain.AccessRequest, validationErr error) *domain.Decision {
	_ = s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventError,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "invalid policy set",
		Payload: map[string]any{
			"stage": "validate_policies",
			"error": validationErr.Error(),
		},
	})
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
		_ = s.recordAudit(ctx, domain.AuditEvent{
			TenantID:      req.TenantID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventError,
			Source:        "core/access",
			UpstreamID:    req.Upstream.ID,
			Outcome:       decision.Outcome,
			Artifact:      decision.Artifact,
			Message:       "invalid-policy decision persistence failed",
			Payload: map[string]any{
				"stage": "persist_invalid_policy_decision",
				"error": recordErr.Error(),
			},
		})
		s.logger.Error("failed to record invalid-policy decision",
			"error", recordErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	}

	return &decision
}

func filterPoliciesForUpstream(policies []domain.Policy, upstreamID string) []domain.Policy {
	if upstreamID == "" {
		return policies
	}

	filtered := make([]domain.Policy, 0, len(policies))
	for _, policyDef := range policies {
		if policyDef.UpstreamID != "" && policyDef.UpstreamID != upstreamID {
			continue
		}
		filtered = append(filtered, policyDef)
	}
	return filtered
}

func (s *AccessService) recordAudit(ctx context.Context, event domain.AuditEvent) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Record(ctx, event)
}

func (s *AccessService) metadataSummary(metadata *domain.ArtifactMetadata) map[string]any {
	if metadata == nil {
		return map[string]any{"available": false}
	}

	summary := map[string]any{
		"available":            true,
		"license_count":        len(metadata.Licenses),
		"vulnerability_count":  len(metadata.Vulnerabilities),
		"mutable_tag_detected": metadata.IsMutableTag,
	}
	if metadata.PublishedAt != nil {
		summary["published_at"] = metadata.PublishedAt.UTC().Format(time.RFC3339)
	}
	if metadata.MaxCVSS != nil {
		summary["max_cvss"] = *metadata.MaxCVSS
	}
	if s.audit != nil && s.audit.DetailLevel() == domain.AuditDetailLevelFull {
		summary["licenses"] = append([]string(nil), metadata.Licenses...)
		summary["vulnerabilities"] = append([]domain.Vulnerability(nil), metadata.Vulnerabilities...)
	}
	return summary
}
