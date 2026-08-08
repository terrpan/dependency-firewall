package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestDependencyContextService_ResolveMissEnqueuesUnknown(t *testing.T) {
	t.Parallel()

	cache := &stubDependencyContextCache{err: domain.ErrCacheMiss}
	graphs := &stubDependencyGraphRepository{lookupErr: domain.ErrArtifactNotFound}
	queue := &stubDependencyGraphQueue{enqueued: true}
	svc := NewDependencyContextService(cache, graphs, queue, slog.Default())

	dependencyContext, enqueued, err := svc.Resolve(context.Background(), dependencyContextRequest())

	require.NoError(t, err)
	assert.True(t, enqueued)
	assert.Equal(t, domain.DependencyScopeUnknown, dependencyContext.Scope)
	assert.NotEmpty(t, dependencyContext.ContextHash)
	assert.Equal(t, 1, queue.calls)
}

func TestDependencyContextService_ResolveTarballMissSkipsEnqueue(t *testing.T) {
	t.Parallel()

	cache := &stubDependencyContextCache{err: domain.ErrCacheMiss}
	graphs := &stubDependencyGraphRepository{lookupErr: domain.ErrArtifactNotFound}
	queue := &stubDependencyGraphQueue{enqueued: true}
	svc := NewDependencyContextService(cache, graphs, queue, slog.Default())

	req := dependencyContextRequest()
	req.Kind = domain.AccessRequestKindNPMTarball
	dependencyContext, enqueued, err := svc.Resolve(context.Background(), req)

	require.NoError(t, err)
	assert.False(t, enqueued)
	assert.Equal(t, domain.DependencyScopeUnknown, dependencyContext.Scope)
	assert.Equal(t, 0, queue.calls)
}

func TestDependencyContextService_ResolveHitSkipsEnqueue(t *testing.T) {
	t.Parallel()

	cacheContext := domain.DependencyContext{
		Scope:           domain.DependencyScopeTransitive,
		DependencyTypes: []domain.DependencyType{domain.DependencyTypePeer},
		GraphIDs:        []string{"graph-1"},
	}.Normalize()
	cache := &stubDependencyContextCache{dependencyContext: &cacheContext}
	queue := &stubDependencyGraphQueue{enqueued: true}
	svc := NewDependencyContextService(cache, nil, queue, slog.Default())

	dependencyContext, enqueued, err := svc.Resolve(context.Background(), dependencyContextRequest())

	require.NoError(t, err)
	assert.False(t, enqueued)
	assert.Equal(t, domain.DependencyScopeTransitive, dependencyContext.Scope)
	assert.Equal(t, []domain.DependencyType{domain.DependencyTypePeer}, dependencyContext.DependencyTypes)
	assert.Equal(t, 0, queue.calls)
}

func TestShouldResolveDependencyContext(t *testing.T) {
	t.Parallel()

	req := dependencyContextRequest()
	targeted := []domain.Policy{{Enabled: true, Target: &domain.PolicyTarget{DependencyScopes: []domain.DependencyScope{domain.DependencyScopeDirect}}}}

	assert.True(t, shouldResolveDependencyContext(req, targeted))

	req.Artifact.Version = ""
	assert.False(t, shouldResolveDependencyContext(req, targeted))
	assert.False(t, shouldResolveDependencyContext(dependencyContextRequest(), []domain.Policy{{Enabled: true}}))
}

func dependencyContextRequest() domain.AccessRequest {
	return domain.AccessRequest{
		TenantID: "tenant-1",
		Upstream: domain.Upstream{
			ID:        "upstream-1",
			Ecosystem: domain.EcosystemNPM,
			BaseURL:   "https://registry.npmjs.org",
		},
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "left-pad",
			Version:   "1.3.0",
		},
	}
}

type stubDependencyContextCache struct {
	dependencyContext *domain.DependencyContext
	err               error
}

func (s *stubDependencyContextCache) Get(context.Context, domain.DependencyContextSummaryKey) (*domain.DependencyContext, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.dependencyContext, nil
}

func (s *stubDependencyContextCache) Set(context.Context, domain.DependencyContextSummaryKey, domain.DependencyContext, time.Duration) error {
	return nil
}

type stubDependencyGraphRepository struct {
	lookupErr error
}

func (s *stubDependencyGraphRepository) EnqueueResolve(context.Context, domain.DependencyGraphResolveRequest) (bool, error) {
	return false, nil
}

func (s *stubDependencyGraphRepository) ClaimNextResolveJob(context.Context, time.Time) (*domain.DependencyGraphResolveRequest, error) {
	return nil, nil
}

func (s *stubDependencyGraphRepository) CompleteResolve(context.Context, domain.DependencyGraphResolveRequest, []domain.DependencyGraphNode, []domain.DependencyGraphEdge, string) error {
	return nil
}

func (s *stubDependencyGraphRepository) FailResolve(context.Context, domain.DependencyGraphResolveRequest, string, time.Time) error {
	return nil
}

func (s *stubDependencyGraphRepository) LookupContext(context.Context, domain.DependencyContextSummaryKey) (*domain.DependencyContext, error) {
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	ctx := domain.DependencyContext{Scope: domain.DependencyScopeDirect}.Normalize()
	return &ctx, nil
}

type stubDependencyGraphQueue struct {
	enqueued bool
	calls    int
}

func (s *stubDependencyGraphQueue) EnqueueResolve(context.Context, domain.DependencyGraphResolveRequest) (bool, error) {
	s.calls++
	return s.enqueued, nil
}
