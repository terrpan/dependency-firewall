package service

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func (s *AccessService) denyForInvalidPolicySet(
	ctx context.Context,
	req domain.AccessRequest,
	validationErr error,
) *domain.Decision {
	span := trace.SpanFromContext(ctx)
	recordSpanError(span, validationErr)
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
	s.logger.ErrorContext(ctx, "invalid policy set, denying request",
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

	if shouldCacheDecision(req) {
		ttl := immutableDecisionTTL
		if req.Artifact.IsMutableReference() {
			ttl = mutableDecisionTTL
		}
		if cacheErr := s.decisionCache.Set(ctx, &decision, ttl); cacheErr != nil {
			s.logger.WarnContext(ctx, "failed to cache invalid-policy decision",
				"error", cacheErr,
				"tenant_id", req.TenantID,
			)
		}
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
		s.logger.ErrorContext(ctx, "failed to record invalid-policy decision",
			"error", recordErr,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	}

	return &decision
}
