package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func (s *AccessService) normalizeAccessRequest(
	ctx context.Context,
	req domain.AccessRequest,
) (domain.AccessRequest, error) {
	if err := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventEvaluationStarted,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "evaluation started",
	}); err != nil {
		return req, err
	}

	originalArtifact := req.Artifact
	parentSpan := trace.SpanFromContext(ctx)
	_, normalizeSpan := serviceTracer().Start(ctx, "access.normalize_artifact")
	normalized, err := domain.NormalizeArtifactIdentity(req.Artifact)
	if err != nil {
		recordSpanError(normalizeSpan, err)
		normalizeSpan.End()
		recordSpanError(parentSpan, err)
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
		return req, fmt.Errorf("normalizing artifact: %w", err)
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
		return req, err
	}

	return req, nil
}

func (s *AccessService) resolveMutableOCIReference(
	ctx context.Context,
	req domain.AccessRequest,
) (domain.AccessRequest, bool, error) {
	if req.Artifact.Ecosystem != domain.EcosystemOCI || !req.Artifact.IsMutableReference() {
		return req, false, nil
	}

	resolveCtx, resolveSpan := serviceTracer().Start(ctx, "access.resolve_reference")
	defer resolveSpan.End()
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
		return req, true, nil
	}

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
		return req, true, nil
	}

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
		return req, true, err
	}

	return req, true, nil
}

func (s *AccessService) resolveMutableNPMReference(
	ctx context.Context,
	req domain.AccessRequest,
) (domain.AccessRequest, error) {
	if !req.Artifact.IsNPMDistTag() {
		return req, nil
	}

	resolveCtx, resolveSpan := serviceTracer().Start(ctx, "access.resolve_reference")
	defer resolveSpan.End()
	resolveSpan.SetAttributes(attribute.String("upstream.id", req.Upstream.ID))

	upstream := req.Upstream
	if upstream.ID == "" {
		up, upErr := s.upstreamRepo.GetByEcosystem(ctx, req.TenantID, domain.EcosystemNPM)
		if upErr != nil {
			recordSpanErrorIfUnexpected(resolveSpan, upErr)
			resolveSpan.SetAttributes(attribute.Bool("reference_resolution.fallback_to_tag", true))
			s.logger.Debug("no npm upstream for tag resolution, continuing with tag",
				"error", upErr,
				"tenant_id", req.TenantID,
			)
			return req, nil
		}
		upstream = *up
	}

	version, resolveErr := s.upstreamClient.ResolveReference(resolveCtx, upstream, req.Artifact)
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
		s.logger.Warn("npm tag resolution failed, continuing with tag",
			"error", resolveErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
		return req, nil
	}

	distTag := req.Artifact.Version
	req.Artifact.Version = version
	resolveSpan.SetAttributes(attribute.Bool("artifact.version_resolved", true))
	if err := s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventReferenceResolved,
		Source:        "core/access",
		UpstreamID:    upstream.ID,
		Artifact:      req.Artifact,
		Message:       "npm dist-tag resolved to version",
		Payload: map[string]any{
			"dist_tag":         distTag,
			"resolved_version": version,
		},
	}); err != nil {
		return req, err
	}

	return req, nil
}

func (s *AccessService) lookupCachedDecision(
	ctx context.Context,
	req domain.AccessRequest,
) (*domain.Decision, bool, error) {
	if !shouldCacheDecision(req) {
		return nil, false, nil
	}

	cacheCtx, cacheSpan := serviceTracer().Start(ctx, "access.decision_cache_lookup")
	dependencyContextHash := dependencyContextCacheHash(req.DependencyContext)
	cached, err := s.decisionCache.Get(
		cacheCtx,
		req.TenantID,
		req.Artifact,
		scopedDecisionCacheIdentity(req, dependencyContextHash),
	)
	if err == nil {
		cacheSpan.SetAttributes(attribute.Bool("cache.hit", true))
		cacheSpan.End()
		return s.useCachedDecision(ctx, req, cached)
	}

	cacheSpan.SetAttributes(attribute.Bool("cache.hit", false))
	recordSpanErrorIfUnexpected(cacheSpan, err)
	if errors.Is(err, domain.ErrCacheMiss) {
		cacheSpan.AddEvent("cache.miss")
	}
	cacheSpan.End()
	if !errors.Is(err, domain.ErrCacheMiss) {
		s.recordDecisionCacheLookupFailure(ctx, req, err)
		return nil, false, nil
	}
	if err := s.recordDecisionCacheMiss(ctx, req); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

func dependencyContextCacheHash(dependencyContext *domain.DependencyContext) string {
	if dependencyContext == nil {
		return ""
	}
	return dependencyContext.Normalize().ContextHash
}

func (s *AccessService) useCachedDecision(
	ctx context.Context,
	req domain.AccessRequest,
	cached *domain.Decision,
) (*domain.Decision, bool, error) {
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
		Payload: map[string]any{
			"dependency_context": dependencyContextSummary(req.DependencyContext),
		},
	}); auditErr != nil {
		return nil, false, auditErr
	}
	s.logger.Debug("decision cache hit",
		"tenant_id", req.TenantID,
		"artifact", req.Artifact.CacheKey(),
	)
	return cached, true, nil
}

func (s *AccessService) recordDecisionCacheLookupFailure(
	ctx context.Context,
	req domain.AccessRequest,
	err error,
) {
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
}

func (s *AccessService) recordDecisionCacheMiss(ctx context.Context, req domain.AccessRequest) error {
	return s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventDecisionCacheMiss,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       "decision cache miss",
		Payload: map[string]any{
			"dependency_context": dependencyContextSummary(req.DependencyContext),
		},
	})
}

func scopedDecisionCacheIdentity(req domain.AccessRequest, dependencyContextHash string) string {
	if dependencyContextHash == "" {
		dependencyContextHash = "none"
	}
	return req.OrganizationID + ":" + req.TeamID + ":" + req.Upstream.ID + ":" + dependencyContextHash
}
