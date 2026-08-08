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
func (s *DependencyContextService) Resolve(ctx context.Context, req domain.AccessRequest) (domain.DependencyContext, bool, error) {
	if s == nil {
		return domain.NewUnknownDependencyContext(), false, nil
	}
	key := domain.DependencyContextSummaryKey{
		TenantID:   req.TenantID,
		UpstreamID: req.Upstream.ID,
		Artifact:   req.Artifact,
	}

	if s.cache != nil {
		cached, err := s.cache.Get(ctx, key)
		if err == nil {
			return cached.Normalize(), false, nil
		}
		if !errors.Is(err, domain.ErrCacheMiss) {
			s.logger.WarnContext(ctx, "dependency context cache lookup failed",
				"error", err,
				"tenant_id", req.TenantID,
				"artifact", req.Artifact.CacheKey(),
			)
		}
	}

	if s.graphs != nil {
		dependencyContext, err := s.graphs.LookupContext(ctx, key)
		if err == nil {
			normalized := dependencyContext.Normalize()
			if s.cache != nil {
				if cacheErr := s.cache.Set(ctx, key, normalized, dependencyContextCacheTTL); cacheErr != nil {
					s.logger.WarnContext(ctx, "dependency context cache write failed",
						"error", cacheErr,
						"tenant_id", req.TenantID,
						"artifact", req.Artifact.CacheKey(),
					)
				}
			}
			return normalized, false, nil
		}
		if !errors.Is(err, domain.ErrArtifactNotFound) {
			return domain.NewUnknownDependencyContext(), false, fmt.Errorf("looking up dependency context: %w", err)
		}
	}

	enqueued := false
	if !shouldEnqueueDependencyGraphRoot(req) {
		s.logger.DebugContext(ctx, "dependency graph enqueue skipped",
			"tenant_id", req.TenantID,
			"upstream_id", req.Upstream.ID,
			"artifact", req.Artifact.CacheKey(),
			"request_kind", req.Kind,
		)
		return domain.NewUnknownDependencyContext(), false, nil
	}
	if s.queue != nil {
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
		} else {
			enqueued = queued
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
		}
	}

	return domain.NewUnknownDependencyContext(), enqueued, nil
}

func shouldEnqueueDependencyGraphRoot(req domain.AccessRequest) bool {
	return req.Kind != domain.AccessRequestKindNPMTarball
}
