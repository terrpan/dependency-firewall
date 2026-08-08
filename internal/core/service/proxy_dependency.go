package service

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func (s *AccessService) attachDependencyContext(
	ctx context.Context,
	req domain.AccessRequest,
	policies []domain.Policy,
) (domain.AccessRequest, error) {
	if !shouldResolveDependencyContext(req, policies) {
		return req, nil
	}

	dependencyContext, enqueued, err := s.dependencies.Resolve(ctx, req)
	if err != nil {
		return req, err
	}
	dependencyContext = dependencyContext.Normalize()
	req.DependencyContext = &dependencyContext

	eventMessage := "dependency graph context hit"
	if dependencyContext.Scope == domain.DependencyScopeUnknown {
		eventMessage = "dependency graph context unknown"
	}
	payload := map[string]any{
		"stage":              "dependency_context",
		"dependency_context": dependencyContextSummary(&dependencyContext),
		"resolver_enqueued":  enqueued,
	}
	if enqueued {
		eventMessage = "dependency graph miss; resolver request enqueued"
	}
	return req, s.recordAudit(ctx, domain.AuditEvent{
		TenantID:      req.TenantID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventDependencyGraphContext,
		Source:        "core/access",
		UpstreamID:    req.Upstream.ID,
		Artifact:      req.Artifact,
		Message:       eventMessage,
		Payload:       payload,
	})
}

func shouldResolveDependencyContext(req domain.AccessRequest, policies []domain.Policy) bool {
	return req.Artifact.Ecosystem == domain.EcosystemNPM &&
		req.Artifact.Version != "" &&
		!req.Artifact.IsNPMDistTag() &&
		needsDependencyContext(policies)
}

func dependencyContextSummary(ctx *domain.DependencyContext) map[string]any {
	if ctx == nil {
		return map[string]any{"available": false}
	}
	normalized := ctx.Normalize()
	return map[string]any{
		"available":        true,
		"scope":            normalized.Scope,
		"dependency_types": normalized.DependencyTypes,
		"graph_ids":        normalized.GraphIDs,
		"context_hash":     normalized.ContextHash,
	}
}
