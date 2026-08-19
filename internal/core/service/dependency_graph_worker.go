package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/infra/npmgraph"
)

// DependencyGraphWorkerConfig configures the npm dependency graph resolver.
type DependencyGraphWorkerConfig struct {
	Enabled      bool
	TenantID     string
	PollInterval time.Duration
	Timeout      time.Duration
	Concurrency  int
	RetryDelay   time.Duration
}

// DependencyGraphWorker resolves npm dependency graphs outside the proxy request path.
type DependencyGraphWorker struct {
	resolver port.DependencyGraphResolver
	watcher  port.DependencyGraphJobWatcher
	cfg      DependencyGraphWorkerConfig
	logger   *slog.Logger
}

// NewDependencyGraphWorker creates a new DependencyGraphWorker. watcher may be
// nil, in which case the worker relies solely on interval polling.
func NewDependencyGraphWorker(
	resolver port.DependencyGraphResolver,
	watcher port.DependencyGraphJobWatcher,
	cfg DependencyGraphWorkerConfig,
	logger *slog.Logger,
) *DependencyGraphWorker {
	return &DependencyGraphWorker{resolver: resolver, watcher: watcher, cfg: cfg, logger: logger}
}

// Run claims and resolves dependency graph jobs until ctx is canceled. New
// jobs are picked up immediately through the optional job watcher; the poll
// ticker remains the fallback for retrying failed jobs and missed signals.
func (w *DependencyGraphWorker) Run(ctx context.Context) error {
	if w == nil || w.resolver == nil || !w.cfg.Enabled {
		<-ctx.Done()
		return nil
	}
	if w.cfg.PollInterval <= 0 {
		w.cfg.PollInterval = 5 * time.Second
	}
	if w.cfg.Timeout <= 0 {
		w.cfg.Timeout = 2 * time.Minute
	}
	if w.cfg.Concurrency <= 0 {
		w.cfg.Concurrency = 1
	}
	if w.cfg.RetryDelay <= 0 {
		w.cfg.RetryDelay = 5 * time.Minute
	}
	w.cfg.TenantID = strings.TrimSpace(w.cfg.TenantID)
	if w.cfg.TenantID == "" {
		w.cfg.TenantID = "*"
	}

	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	sem := make(chan struct{}, w.cfg.Concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()

	var notifications <-chan struct{}
	if w.watcher != nil {
		notifications = w.watcher.WatchResolveJobs(ctx, w.cfg.TenantID)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case _, ok := <-notifications:
			if !ok {
				notifications = nil
				continue
			}
		}
		w.claimAvailableJobs(ctx, sem, &wg)
	}
}

func (w *DependencyGraphWorker) claimAvailableJobs(ctx context.Context, sem chan struct{}, wg *sync.WaitGroup) {
	for len(sem) < cap(sem) {
		job, err := w.resolver.ClaimNextResolveJob(ctx, w.cfg.TenantID, time.Now().UTC())
		if err != nil {
			w.logger.WarnContext(ctx, "dependency graph job claim failed", "error", err)
			return
		}
		if job == nil {
			return
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			w.resolveJob(ctx, *job)
		})
	}
}

func (w *DependencyGraphWorker) resolveJob(ctx context.Context, job domain.DependencyGraphResolveRequest) {
	resolveCtx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()

	startedAt := time.Now().UTC()
	w.logger.InfoContext(ctx, "dependency graph resolution started",
		"tenant_id", job.TenantID,
		"upstream_id", job.Upstream.ID,
		"artifact", job.Root.CacheKey(),
	)

	nodes, edges, graphHash, err := resolveNPMGraph(resolveCtx, job)
	if err != nil {
		retryAfter := time.Now().UTC().Add(w.cfg.RetryDelay)
		if failErr := w.resolver.FailResolve(context.Background(), job, err.Error(), retryAfter); failErr != nil {
			w.logger.WarnContext(ctx, "dependency graph failure persistence failed",
				"error", failErr,
				"tenant_id", job.TenantID,
				"artifact", job.Root.CacheKey(),
			)
		}
		w.logger.WarnContext(ctx, "dependency graph resolution failed",
			"error", err,
			"tenant_id", job.TenantID,
			"upstream_id", job.Upstream.ID,
			"artifact", job.Root.CacheKey(),
			"duration_ms", time.Since(startedAt).Milliseconds(),
		)
		return
	}

	if err := w.resolver.CompleteResolve(context.Background(), job, nodes, edges, graphHash); err != nil {
		w.logger.WarnContext(ctx, "dependency graph completion failed",
			"error", err,
			"tenant_id", job.TenantID,
			"artifact", job.Root.CacheKey(),
		)
		return
	}
	w.logger.InfoContext(ctx, "dependency graph resolved",
		"tenant_id", job.TenantID,
		"upstream_id", job.Upstream.ID,
		"artifact", job.Root.CacheKey(),
		"node_count", len(nodes),
		"edge_count", len(edges),
		"duration_ms", time.Since(startedAt).Milliseconds(),
	)
}

func resolveNPMGraph(
	ctx context.Context,
	job domain.DependencyGraphResolveRequest,
) ([]domain.DependencyGraphNode, []domain.DependencyGraphEdge, string, error) {
	dir, err := os.MkdirTemp("", "dependency-firewall-npm-graph-*")
	if err != nil {
		return nil, nil, "", fmt.Errorf("creating resolver workspace: %w", err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup of a temp workspace; the OS reclaims it regardless

	packageJSON := []byte(`{"private":true,"name":"dependency-firewall-graph-root","version":"0.0.0"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, "package.json"), packageJSON, 0o600); err != nil {
		return nil, nil, "", fmt.Errorf("writing resolver package.json: %w", err)
	}

	args := []string{
		"install",
		job.Root.FullName() + "@" + job.Root.Version,
		"--package-lock-only",
		"--ignore-scripts",
		"--no-audit",
		"--no-fund",
		"--allow-git=none",
	}
	if registry := strings.TrimSpace(job.Upstream.BaseURL); registry != "" {
		args = append(args, "--registry", registry)
	}
	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, "", fmt.Errorf("running npm resolver: %w: %s", err, strings.TrimSpace(string(output)))
	}

	//nolint:gosec // fixed filename inside the os.MkdirTemp workspace created above
	lockData, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, nil, "", fmt.Errorf("reading resolver package-lock.json: %w", err)
	}
	return npmgraph.ParsePackageLock(job.Root, lockData)
}
