package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type stubManifestLister struct {
	mu   sync.Mutex
	deps map[string][]string // "name@version" -> dependency names
	errs map[string]error
}

func (s *stubManifestLister) ListManifestDependencyNames(_ context.Context, _ domain.Upstream, artifact domain.ArtifactIdentity) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := artifact.Name + "@" + artifact.Version
	if err, ok := s.errs[key]; ok {
		return nil, err
	}
	return s.deps[key], nil
}

type recordingGraphQueue struct {
	mu       sync.Mutex
	requests []domain.DependencyGraphResolveRequest
	err      error
}

func (q *recordingGraphQueue) EnqueueResolve(_ context.Context, req domain.DependencyGraphResolveRequest) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return false, q.err
	}
	q.requests = append(q.requests, req)
	return true, nil
}

func snapshotPackages(specs ...string) []domain.ArtifactIdentity {
	packages := make([]domain.ArtifactIdentity, 0, len(specs))
	for _, spec := range specs {
		var name, version string
		for i := len(spec) - 1; i > 0; i-- {
			if spec[i] == '@' {
				name, version = spec[:i], spec[i+1:]
				break
			}
		}
		packages = append(packages, domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      name,
			Version:   version,
		})
	}
	return packages
}

func TestNPMInstallSnapshotService_ProcessSnapshot_InfersSingleRoot(t *testing.T) {
	lister := &stubManifestLister{deps: map[string][]string{
		"morgan@1.10.0":   {"basic-auth", "debug", "on-finished"},
		"basic-auth@2.0.1": {"safe-buffer"},
		"debug@2.6.9":      {"ms"},
		"on-finished@2.3.0": {"ee-first"},
		"safe-buffer@5.1.2": nil,
		"ms@2.0.0":          nil,
		"ee-first@1.1.1":    nil,
	}}
	queue := &recordingGraphQueue{}
	svc := NewNPMInstallSnapshotService(lister, queue, slog.Default())

	snapshot := domain.NPMInstallSnapshot{
		TenantID: "t-1",
		Upstream: domain.Upstream{ID: "up-1", TenantID: "t-1"},
		Packages: snapshotPackages(
			"morgan@1.10.0", "basic-auth@2.0.1", "debug@2.6.9",
			"on-finished@2.3.0", "safe-buffer@5.1.2", "ms@2.0.0", "ee-first@1.1.1",
		),
	}

	roots, err := svc.ProcessSnapshot(context.Background(), snapshot)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Equal(t, "morgan", roots[0].Name)
	assert.Equal(t, "1.10.0", roots[0].Version)

	require.Len(t, queue.requests, 1)
	assert.Equal(t, "t-1", queue.requests[0].TenantID)
	assert.Equal(t, "morgan", queue.requests[0].Root.Name)
}

func TestNPMInstallSnapshotService_ProcessSnapshot_MultipleRoots(t *testing.T) {
	lister := &stubManifestLister{deps: map[string][]string{
		"morgan@1.10.0": {"debug"},
		"express@4.18.2": {"debug"},
		"debug@2.6.9":    nil,
	}}
	queue := &recordingGraphQueue{}
	svc := NewNPMInstallSnapshotService(lister, queue, slog.Default())

	roots, err := svc.ProcessSnapshot(context.Background(), domain.NPMInstallSnapshot{
		TenantID: "t-1",
		Upstream: domain.Upstream{ID: "up-1"},
		Packages: snapshotPackages("morgan@1.10.0", "express@4.18.2", "debug@2.6.9"),
	})
	require.NoError(t, err)
	require.Len(t, roots, 2)
	assert.Len(t, queue.requests, 2)
}

func TestNPMInstallSnapshotService_ProcessSnapshot_SkipsWhenManifestLookupsUnreliable(t *testing.T) {
	lister := &stubManifestLister{errs: map[string]error{
		"morgan@1.10.0": fmt.Errorf("upstream unavailable"),
		"debug@2.6.9":   fmt.Errorf("upstream unavailable"),
	}}
	queue := &recordingGraphQueue{}
	svc := NewNPMInstallSnapshotService(lister, queue, slog.Default())

	roots, err := svc.ProcessSnapshot(context.Background(), domain.NPMInstallSnapshot{
		TenantID: "t-1",
		Upstream: domain.Upstream{ID: "up-1"},
		Packages: snapshotPackages("morgan@1.10.0", "debug@2.6.9"),
	})
	require.NoError(t, err)
	assert.Empty(t, roots)
	assert.Empty(t, queue.requests)
}

func TestNPMInstallSnapshotService_ProcessSnapshot_EmptySnapshot(t *testing.T) {
	svc := NewNPMInstallSnapshotService(&stubManifestLister{}, &recordingGraphQueue{}, slog.Default())
	roots, err := svc.ProcessSnapshot(context.Background(), domain.NPMInstallSnapshot{TenantID: "t-1"})
	require.NoError(t, err)
	assert.Empty(t, roots)
}

func TestNPMInstallSnapshotService_ProcessSnapshot_NilService(t *testing.T) {
	var svc *NPMInstallSnapshotService
	roots, err := svc.ProcessSnapshot(context.Background(), domain.NPMInstallSnapshot{})
	require.NoError(t, err)
	assert.Empty(t, roots)
}

func TestNPMInstallSnapshotService_ProcessSnapshot_DedupesPackages(t *testing.T) {
	lister := &stubManifestLister{deps: map[string][]string{
		"morgan@1.10.0": {"debug"},
		"debug@2.6.9":   nil,
	}}
	queue := &recordingGraphQueue{}
	svc := NewNPMInstallSnapshotService(lister, queue, slog.Default())

	roots, err := svc.ProcessSnapshot(context.Background(), domain.NPMInstallSnapshot{
		TenantID: "t-1",
		Upstream: domain.Upstream{ID: "up-1"},
		Packages: snapshotPackages("morgan@1.10.0", "morgan@1.10.0", "debug@2.6.9"),
	})
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Len(t, queue.requests, 1)
}
