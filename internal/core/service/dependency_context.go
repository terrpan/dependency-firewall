package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

const dependencyContextCacheTTL = 30 * time.Minute

// DependencyContextService attaches async graph-backed npm dependency context to access requests.
type DependencyContextService struct {
	cache  port.DependencyContextCache
	graphs port.DependencyGraphContextLookup
	queue  port.DependencyGraphQueue
	logger *slog.Logger
}

// NewDependencyContextService creates a new DependencyContextService.
func NewDependencyContextService(
	cache port.DependencyContextCache,
	graphs port.DependencyGraphContextLookup,
	queue port.DependencyGraphQueue,
	logger *slog.Logger,
) *DependencyContextService {
	return &DependencyContextService{
		cache:  cache,
		graphs: graphs,
		queue:  queue,
		logger: logger,
	}
}

// Resolve returns the best available context and whether an async resolve job was enqueued.
func (s *DependencyContextService) Resolve(
	ctx context.Context,
	req domain.AccessRequest,
) (domain.DependencyContext, bool, error) {
	if s == nil {
		return domain.NewUnknownDependencyContext(), false, nil
	}
	key := dependencyContextKey(req)

	if cached, ok := s.lookupCachedContext(ctx, req, key); ok {
		return cached, false, nil
	}
	stored, ok, err := s.lookupStoredContext(ctx, req, key)
	if err != nil {
		return domain.NewUnknownDependencyContext(), false, err
	}
	if ok {
		return stored, false, nil
	}

	enqueued := s.enqueueDependencyGraphRoot(ctx, req)
	return domain.NewUnknownDependencyContext(), enqueued, nil
}

func dependencyContextKey(req domain.AccessRequest) domain.DependencyContextSummaryKey {
	return domain.DependencyContextSummaryKey{
		TenantID:   req.TenantID,
		UpstreamID: req.Upstream.ID,
		Artifact:   req.Artifact,
	}
}

func (s *DependencyContextService) lookupCachedContext(
	ctx context.Context,
	req domain.AccessRequest,
	key domain.DependencyContextSummaryKey,
) (domain.DependencyContext, bool) {
	if s.cache == nil {
		return domain.DependencyContext{}, false
	}
	cached, err := s.cache.Get(ctx, key)
	if err == nil {
		return cached.Normalize(), true
	}
	if !errors.Is(err, domain.ErrCacheMiss) {
		s.logger.WarnContext(ctx, "dependency context cache lookup failed",
			"error", err,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	}
	return domain.DependencyContext{}, false
}

func (s *DependencyContextService) lookupStoredContext(
	ctx context.Context,
	req domain.AccessRequest,
	key domain.DependencyContextSummaryKey,
) (domain.DependencyContext, bool, error) {
	if s.graphs == nil {
		return domain.DependencyContext{}, false, nil
	}
	dependencyContext, err := s.graphs.LookupContext(ctx, key)
	if errors.Is(err, domain.ErrArtifactNotFound) {
		return domain.DependencyContext{}, false, nil
	}
	if err != nil {
		return domain.DependencyContext{}, false, fmt.Errorf("looking up dependency context: %w", err)
	}

	normalized := dependencyContext.Normalize()
	s.cacheStoredContext(ctx, req, key, normalized)
	return normalized, true, nil
}

func (s *DependencyContextService) cacheStoredContext(
	ctx context.Context,
	req domain.AccessRequest,
	key domain.DependencyContextSummaryKey,
	dependencyContext domain.DependencyContext,
) {
	if s.cache == nil {
		return
	}
	if err := s.cache.Set(ctx, key, dependencyContext, dependencyContextCacheTTL); err != nil {
		s.logger.WarnContext(ctx, "dependency context cache write failed",
			"error", err,
			"tenant_id", req.TenantID,
			"artifact", req.Artifact.CacheKey(),
		)
	}
}

func (s *DependencyContextService) enqueueDependencyGraphRoot(
	ctx context.Context,
	req domain.AccessRequest,
) bool {
	if !shouldEnqueueDependencyGraphRoot(req) {
		s.logger.DebugContext(ctx, "dependency graph enqueue skipped",
			"tenant_id", req.TenantID,
			"upstream_id", req.Upstream.ID,
			"artifact", req.Artifact.CacheKey(),
			"request_kind", req.Kind,
		)
		return false
	}
	if s.queue == nil {
		return false
	}

	queued, err := s.queue.EnqueueResolve(ctx, domain.DependencyGraphResolveRequest{
		TenantID:    req.TenantID,
		Upstream:    req.Upstream,
		Root:        req.Artifact,
		RequestedAt: time.Now().UTC(),
	})
	if err != nil {
		s.logger.WarnContext(ctx, "dependency graph enqueue failed",
			"error", err,
			"tenant_id", req.TenantID,
			"upstream_id", req.Upstream.ID,
			"artifact", req.Artifact.CacheKey(),
		)
		return false
	}
	if queued {
		s.logger.InfoContext(ctx, "dependency graph resolve enqueued",
			"tenant_id", req.TenantID,
			"upstream_id", req.Upstream.ID,
			"artifact", req.Artifact.CacheKey(),
		)
	} else {
		s.logger.DebugContext(ctx, "dependency graph resolve already queued",
			"tenant_id", req.TenantID,
			"upstream_id", req.Upstream.ID,
			"artifact", req.Artifact.CacheKey(),
		)
	}
	return queued
}

func shouldEnqueueDependencyGraphRoot(req domain.AccessRequest) bool {
	return req.Kind != domain.AccessRequestKindNPMTarball
}
