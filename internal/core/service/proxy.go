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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
	ctx, span := tracer.Start(ctx, "access.evaluate")
	span.SetAttributes(accessRequestAttributes(req)...)
	defer span.End()

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
	_, normalizeSpan := tracer.Start(ctx, "access.normalize_artifact")
	normalized, err := domain.NormalizeArtifactIdentity(req.Artifact)
	if err != nil {
		recordSpanError(normalizeSpan, err)
		normalizeSpan.End()
		recordSpanError(span, err)
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
	normalizeSpan.End()
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
		resolveCtx, resolveSpan := tracer.Start(ctx, "access.resolve_reference")
		resolveSpan.SetAttributes(attribute.String("upstream.id", req.Upstream.ID))
		upstream := req.Upstream
		if upstream.ID == "" {
			up, upErr := s.upstreamRepo.GetByEcosystem(ctx, req.TenantID, domain.EcosystemOCI)
			if upErr != nil {
				recordSpanErrorIfUnexpected(resolveSpan, upErr)
				resolveSpan.SetAttributes(attribute.Bool("reference_resolution.fallback_to_tag", true))
				s.logger.Debug("no OCI upstream for tag resolution, continuing with tag",
					"error", upErr,
					"tenant_id", req.TenantID,
				)
			} else {
				upstream = *up
			}
		}
		if upstream.ID == "" {
			resolveSpan.SetAttributes(
				attribute.Bool("reference_resolution.skipped", true),
				attribute.Bool("reference_resolution.fallback_to_tag", true),
			)
			s.logger.Debug("no OCI upstream for tag resolution, continuing with tag",
				"tenant_id", req.TenantID,
			)
		} else {
			digest, resolveErr := s.upstreamClient.ResolveReference(resolveCtx, upstream, req.Artifact)
			if resolveErr != nil {
				recordSpanErrorIfUnexpected(resolveSpan, resolveErr)
				resolveSpan.SetAttributes(attribute.Bool("reference_resolution.fallback_to_tag", true))
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
				resolveSpan.SetAttributes(attribute.Bool("artifact.digest_resolved", true))
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
		resolveSpan.End()
	}

	// 2. Check decision cache.
	cacheCtx, cacheSpan := tracer.Start(ctx, "access.decision_cache_lookup")
	cached, err := s.decisionCache.Get(cacheCtx, req.TenantID, req.Artifact)
	if err == nil {
		cacheSpan.SetAttributes(attribute.Bool("cache.hit", true))
		cacheSpan.End()
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
		span.SetAttributes(attribute.Bool("cache.hit", true))
		return cached, nil
	}
	cacheSpan.SetAttributes(attribute.Bool("cache.hit", false))
	recordSpanErrorIfUnexpected(cacheSpan, err)
	if errors.Is(err, domain.ErrCacheMiss) {
		cacheSpan.AddEvent("cache.miss")
	}
	cacheSpan.End()
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

	// 3. Load tenant policies before enrichment so default-allow traffic does
	// not pay for metadata lookups when no enabled policy can inspect metadata.
	policiesCtx, policiesSpan := tracer.Start(ctx, "access.load_policies")
	policies, err := s.policies.ListByTenant(policiesCtx, req.TenantID)
	if err != nil {
		recordSpanError(policiesSpan, err)
		policiesSpan.End()
		recordSpanError(span, err)
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
	policiesSpan.SetAttributes(attribute.Int("policy.tenant_count", len(policies)))
	policiesSpan.End()
	if err := policy.ValidatePolicies(policies); err != nil {
		recordSpanError(span, err)
		return s.denyForInvalidPolicySet(ctx, req, err), nil
	}
	effectivePolicies := filterPoliciesForUpstream(policies, req.Upstream.ID)
	policyHash, err := policy.HashPolicies(effectivePolicies)
	if err != nil {
		recordSpanError(span, err)
		return s.denyForInvalidPolicySet(ctx, req, err), nil
	}
	span.SetAttributes(attribute.Int("policy.effective_count", len(effectivePolicies)))
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

	var metadata *domain.ArtifactMetadata
	if needsEnrichment(effectivePolicies) {
		metadata, err = s.enrichArtifact(ctx, req)
		if err != nil {
			recordSpanError(span, err)
			return nil, err
		}
		req.Metadata = metadata
	}

	// 4b. Propagate mutable-tag flag so the block_mutable_tag condition can detect it.
	applyMutableTagMetadata(&req, wasMutableTag)

	// 6. Run policy evaluator.
	_, evaluateSpan := tracer.Start(ctx, "access.evaluate_policies")
	decision := s.evaluator.Evaluate(req, effectivePolicies)
	evaluateSpan.SetAttributes(
		attribute.String("decision.outcome", string(decision.Outcome)),
		attribute.Int("decision.reason_count", len(decision.Reasons)),
	)
	evaluateSpan.End()
	decision.PolicyHash = policyHash
	span.SetAttributes(
		attribute.String("decision.outcome", string(decision.Outcome)),
		attribute.Int("decision.reason_count", len(decision.Reasons)),
	)
	for _, reason := range decision.Reasons {
		span.AddEvent("policy.matched", trace.WithAttributes(
			attribute.String("policy.id", reason.PolicyID),
			attribute.String("policy.name", reason.PolicyName),
			attribute.String("reason.category", string(reason.Category)),
			attribute.String("policy.action", string(reason.Action)),
		))
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
	cacheWriteCtx, cacheWriteSpan := tracer.Start(ctx, "access.cache_decision")
	if cacheErr := s.decisionCache.Set(cacheWriteCtx, &decision, ttl); cacheErr != nil {
		recordSpanError(cacheWriteSpan, cacheErr)
		s.logger.WarnContext(ctx, "failed to cache decision",
			"error", cacheErr,
			"tenant_id", req.TenantID,
		)
	}
	cacheWriteSpan.SetAttributes(attribute.Int64("cache.ttl_ms", ttl.Milliseconds()))
	cacheWriteSpan.End()

	// 8. Record the decision in the repository.
	recordCtx, recordSpan := tracer.Start(ctx, "access.persist_decision")
	if recordErr := s.decisions.Record(recordCtx, &decision); recordErr != nil {
		recordSpanError(recordSpan, recordErr)
		recordSpan.End()
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
		s.logger.ErrorContext(ctx, "failed to record decision",
			"error", recordErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
		recordSpanError(span, recordErr)
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
		recordSpanError(recordSpan, auditErr)
		recordSpan.End()
		recordSpanError(span, auditErr)
		return nil, auditErr
	} else {
		recordSpan.End()
	}

	return &decision, nil
}

// HasRecentAllow checks if there's a recent allow decision for the given
// repository identity (tenant + ecosystem + namespace + name).
func (s *AccessService) HasRecentAllow(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (bool, error) {
	return s.decisions.HasRecentAllow(ctx, tenantID, artifact.Ecosystem, artifact.Namespace, artifact.Name)
}
