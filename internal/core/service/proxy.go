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
	dependencies   *DependencyContextService
	enrichment     *EnrichmentService
	evaluator      *policy.Evaluator
	upstreamClient port.UpstreamClient
	upstreamRepo   port.UpstreamRepository
	logger         *slog.Logger
	audit          *AuditService
}

// AccessServiceOption customizes AccessService construction.
type AccessServiceOption func(*AccessService)

// WithDependencyContextService enables graph-backed dependency context.
func WithDependencyContextService(dependencies *DependencyContextService) AccessServiceOption {
	return func(s *AccessService) {
		s.dependencies = dependencies
	}
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
	audit *AuditService,
	options ...AccessServiceOption,
) *AccessService {
	svc := &AccessService{
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
	for _, option := range options {
		option(svc)
	}
	return svc
}

// Evaluate processes an access request through the full pipeline:
// normalize -> load policies -> attach dependency context -> check decision cache -> enrich -> evaluate policies -> cache decision -> record decision.
func (s *AccessService) Evaluate(ctx context.Context, req domain.AccessRequest) (*domain.Decision, error) {
	ctx, span := serviceTracer().Start(ctx, "access.evaluate")
	span.SetAttributes(accessRequestAttributes(req)...)
	defer span.End()

	// 1. Normalize the artifact identity.
	req, err := s.normalizeAccessRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	// 1b. Resolve OCI mutable tags to digests for stable cache keys.
	req, wasMutableTag, err := s.resolveMutableOCIReference(ctx, req)
	if err != nil {
		return nil, err
	}

	// 1c. Resolve npm dist-tags (e.g. "latest") to concrete versions so
	// enrichment and policy evaluation target the version actually requested.
	req, err = s.resolveMutableNPMReference(ctx, req)
	if err != nil {
		return nil, err
	}

	// 2. Load tenant policies before enrichment so default-allow traffic does
	// not pay for metadata lookups when no enabled policy can inspect metadata.
	policySet, invalidDecision, err := s.preparePolicySet(ctx, req)
	if invalidDecision != nil {
		return invalidDecision, nil
	}
	if err != nil {
		return nil, err
	}

	// 3. Attach dependency context only when target-aware policies are enabled.
	req, err = s.attachDependencyContext(ctx, req, policySet.effectivePolicies)
	if err != nil {
		return nil, err
	}

	// 4. Check decision cache after context attachment so graph-sensitive
	// decisions do not reuse artifact-only cache entries.
	cached, hit, err := s.lookupCachedDecision(ctx, req)
	if err != nil {
		return nil, err
	}
	if hit {
		span.SetAttributes(attribute.Bool("cache.hit", true))
		return cached, nil
	}

	var metadata *domain.ArtifactMetadata
	if shouldEnrichArtifact(req, policySet.effectivePolicies) {
		metadata, err = s.enrichArtifact(ctx, req)
		if err != nil {
			recordSpanError(span, err)
			return nil, err
		}
		req.Metadata = metadata
	}

	// 5. Propagate mutable-tag flag so the block_mutable_tag condition can detect it.
	applyMutableTagMetadata(&req, wasMutableTag)

	// 6. Run policy evaluator.
	decision, err := s.evaluatePolicies(ctx, req, policySet, metadata)
	if err != nil {
		return nil, err
	}

	// 7. Cache the decision (shorter TTL for mutable references).
	// 8. Record the decision in the repository.
	if err := s.finalizeDecision(ctx, req, decision); err != nil {
		return nil, err
	}

	return decision, nil
}

type preparedPolicySet struct {
	effectivePolicies []domain.Policy
	hash              string
}

func (s *AccessService) preparePolicySet(
	ctx context.Context,
	req domain.AccessRequest,
) (*preparedPolicySet, *domain.Decision, error) {
	parentSpan := trace.SpanFromContext(ctx)
	policiesCtx, policiesSpan := serviceTracer().Start(ctx, "access.load_policies")
	policies, err := s.policies.ListByTenant(policiesCtx, req.TenantID)
	if err != nil {
		recordSpanError(policiesSpan, err)
		policiesSpan.End()
		recordSpanError(parentSpan, err)
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			return nil, s.denyForInvalidPolicySet(ctx, req, err), nil
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
		return nil, nil, fmt.Errorf("loading policies: %w", err)
	}
	policiesSpan.SetAttributes(attribute.Int("policy.tenant_count", len(policies)))
	policiesSpan.End()

	if err := policy.ValidatePolicies(policies); err != nil {
		recordSpanError(parentSpan, err)
		return nil, s.denyForInvalidPolicySet(ctx, req, err), nil
	}

	effectivePolicies := filterPoliciesForUpstream(policies, req.Upstream.ID)
	policyHash, err := policy.HashPolicies(effectivePolicies)
	if err != nil {
		recordSpanError(parentSpan, err)
		return nil, s.denyForInvalidPolicySet(ctx, req, err), nil
	}

	parentSpan.SetAttributes(attribute.Int("policy.effective_count", len(effectivePolicies)))
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
		return nil, nil, err
	}

	return &preparedPolicySet{
		effectivePolicies: effectivePolicies,
		hash:              policyHash,
	}, nil, nil
}

func (s *AccessService) evaluatePolicies(
	ctx context.Context,
	req domain.AccessRequest,
	policySet *preparedPolicySet,
	metadata *domain.ArtifactMetadata,
) (*domain.Decision, error) {
	parentSpan := trace.SpanFromContext(ctx)
	_, evaluateSpan := serviceTracer().Start(ctx, "access.evaluate_policies")
	decision := s.evaluator.Evaluate(req, policySet.effectivePolicies)
	evaluateSpan.SetAttributes(
		attribute.String("decision.outcome", string(decision.Outcome)),
		attribute.Int("decision.reason_count", len(decision.Reasons)),
	)
	evaluateSpan.End()

	decision.PolicyHash = policySet.hash
	if req.DependencyContext != nil {
		dependencyContext := req.DependencyContext.Normalize()
		decision.DependencyContext = &dependencyContext
	}
	parentSpan.SetAttributes(
		attribute.String("decision.outcome", string(decision.Outcome)),
		attribute.Int("decision.reason_count", len(decision.Reasons)),
	)
	for _, reason := range decision.Reasons {
		parentSpan.AddEvent("policy.matched", trace.WithAttributes(
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
	if shouldPersistDecision(req, &decision) {
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
				"dependency_context": dependencyContextSummary(decision.DependencyContext),
			},
		}); err != nil {
			return nil, err
		}
	}

	return &decision, nil
}

func (s *AccessService) finalizeDecision(
	ctx context.Context,
	req domain.AccessRequest,
	decision *domain.Decision,
) error {
	if shouldCacheDecision(req) {
		ttl := immutableDecisionTTL
		if req.Artifact.IsMutableReference() {
			ttl = mutableDecisionTTL
		}
		cacheWriteCtx, cacheWriteSpan := serviceTracer().Start(ctx, "access.cache_decision")
		if cacheErr := s.decisionCache.Set(cacheWriteCtx, decision, ttl); cacheErr != nil {
			recordSpanError(cacheWriteSpan, cacheErr)
			s.logger.WarnContext(ctx, "failed to cache decision",
				"error", cacheErr,
				"tenant_id", req.TenantID,
			)
		}
		cacheWriteSpan.SetAttributes(attribute.Int64("cache.ttl_ms", ttl.Milliseconds()))
		cacheWriteSpan.End()
	}

	if !shouldPersistDecision(req, decision) {
		return nil
	}

	parentSpan := trace.SpanFromContext(ctx)
	recordCtx, recordSpan := serviceTracer().Start(ctx, "access.persist_decision")
	if recordErr := s.decisions.Record(recordCtx, decision); recordErr != nil {
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
		recordSpanError(parentSpan, recordErr)
		return nil
	}

	if auditErr := s.recordAudit(ctx, domain.AuditEvent{
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
			"policy_hash":        decision.PolicyHash,
			"dependency_context": dependencyContextSummary(decision.DependencyContext),
		},
	}); auditErr != nil {
		recordSpanError(recordSpan, auditErr)
		recordSpan.End()
		recordSpanError(parentSpan, auditErr)
		return auditErr
	}

	recordSpan.End()
	return nil
}

// HasRecentAllow checks if there's a recent allow decision for the given
// repository identity (tenant + ecosystem + namespace + name).
func (s *AccessService) HasRecentAllow(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (bool, error) {
	return s.decisions.HasRecentAllow(ctx, tenantID, artifact.Ecosystem, artifact.Namespace, artifact.Name)
}
