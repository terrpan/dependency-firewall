package service

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

const (
	defaultSnapshotManifestConcurrency = 8
	// snapshotMaxPackages bounds how many snapshot packages are inspected so a
	// hostile or pathological audit payload cannot fan out unbounded fetches.
	snapshotMaxPackages = 5000
)

// NPMInstallSnapshotService infers dependency graph roots from npm install
// snapshots and enqueues async graph-resolution jobs for those roots only.
//
// Root inference is a name-level set difference: a snapshot package is a root
// when no other package in the same snapshot declares its name as a dependency.
type NPMInstallSnapshotService struct {
	manifests   port.NPMManifestDependencyLister
	queue       port.DependencyGraphQueue
	logger      *slog.Logger
	concurrency int
}

// NewNPMInstallSnapshotService creates a new NPMInstallSnapshotService.
func NewNPMInstallSnapshotService(
	manifests port.NPMManifestDependencyLister,
	queue port.DependencyGraphQueue,
	logger *slog.Logger,
) *NPMInstallSnapshotService {
	return &NPMInstallSnapshotService{
		manifests:   manifests,
		queue:       queue,
		logger:      logger,
		concurrency: defaultSnapshotManifestConcurrency,
	}
}

// ProcessSnapshot infers the root packages of an install snapshot and enqueues
// one graph-resolution job per root. It returns the inferred roots.
func (s *NPMInstallSnapshotService) ProcessSnapshot(
	ctx context.Context,
	snapshot domain.NPMInstallSnapshot,
) ([]domain.ArtifactIdentity, error) {
	if s == nil || s.manifests == nil || s.queue == nil {
		return nil, nil
	}
	packages := dedupeSnapshotPackages(snapshot.Packages)
	if len(packages) == 0 {
		return nil, nil
	}
	if len(packages) > snapshotMaxPackages {
		s.logger.WarnContext(ctx, "npm install snapshot truncated",
			"tenant_id", snapshot.TenantID,
			"package_count", len(packages),
			"max_packages", snapshotMaxPackages,
		)
		packages = packages[:snapshotMaxPackages]
	}

	dependedOn, fetchFailures := s.collectDependencyNames(ctx, snapshot.Upstream, packages)

	roots := make([]domain.ArtifactIdentity, 0)
	for _, pkg := range packages {
		if _, ok := dependedOn[pkg.Name]; !ok {
			roots = append(roots, pkg)
		}
	}

	// If manifest lookups failed and the set difference degenerated into "every
	// package is a root", inference is unreliable; skip rather than fan out.
	if fetchFailures > 0 && len(packages) > 1 && len(roots) == len(packages) {
		s.logger.WarnContext(ctx, "npm install snapshot root inference skipped: manifest lookups unreliable",
			"tenant_id", snapshot.TenantID,
			"package_count", len(packages),
			"fetch_failures", fetchFailures,
		)
		return nil, nil
	}

	requestedAt := snapshot.ObservedAt
	if requestedAt.IsZero() {
		requestedAt = time.Now().UTC()
	}
	for _, root := range roots {
		enqueued, err := s.queue.EnqueueResolve(ctx, domain.DependencyGraphResolveRequest{
			TenantID:    snapshot.TenantID,
			Upstream:    snapshot.Upstream,
			Root:        root,
			RequestedAt: requestedAt,
		})
		if err != nil {
			s.logger.WarnContext(ctx, "npm install snapshot root enqueue failed",
				"error", err,
				"tenant_id", snapshot.TenantID,
				"root", root.CacheKey(),
			)
			continue
		}
		if enqueued {
			s.logger.InfoContext(ctx, "npm install snapshot root enqueued",
				"tenant_id", snapshot.TenantID,
				"upstream_id", snapshot.Upstream.ID,
				"root", root.CacheKey(),
				"package_count", len(packages),
			)
		}
	}
	return roots, nil
}

// collectDependencyNames fetches each snapshot package manifest with bounded
// concurrency and returns the union of declared dependency names plus the
// number of manifests that could not be inspected.
func (s *NPMInstallSnapshotService) collectDependencyNames(
	ctx context.Context,
	upstream domain.Upstream,
	packages []domain.ArtifactIdentity,
) (map[string]struct{}, int) {
	var (
		mu            sync.Mutex
		wg            sync.WaitGroup
		dependedOn    = make(map[string]struct{})
		fetchFailures int
	)
	sem := make(chan struct{}, s.concurrency)
	for _, pkg := range packages {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(pkg domain.ArtifactIdentity) {
			defer wg.Done()
			defer func() { <-sem }()
			names, err := s.manifests.ListManifestDependencyNames(ctx, upstream, pkg)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fetchFailures++
				s.logger.DebugContext(ctx, "npm manifest dependency lookup failed",
					"error", err,
					"artifact", pkg.CacheKey(),
				)
				return
			}
			for _, name := range names {
				dependedOn[name] = struct{}{}
			}
		}(pkg)
	}
	wg.Wait()
	return dependedOn, fetchFailures
}

func dedupeSnapshotPackages(packages []domain.ArtifactIdentity) []domain.ArtifactIdentity {
	seen := make(map[string]struct{}, len(packages))
	result := make([]domain.ArtifactIdentity, 0, len(packages))
	for _, pkg := range packages {
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		key := pkg.Name + "@" + pkg.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, pkg)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].Version < result[j].Version
	})
	return result
}
