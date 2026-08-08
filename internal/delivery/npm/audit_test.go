package npm

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

type stubManifestLister struct {
	deps map[string][]string
}

func (s *stubManifestLister) ListManifestDependencyNames(_ context.Context, _ domain.Upstream, artifact domain.ArtifactIdentity) ([]string, error) {
	return s.deps[artifact.Name+"@"+artifact.Version], nil
}

type recordingGraphQueue struct {
	mu       sync.Mutex
	requests []domain.DependencyGraphResolveRequest
}

func (q *recordingGraphQueue) EnqueueResolve(_ context.Context, req domain.DependencyGraphResolveRequest) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requests = append(q.requests, req)
	return true, nil
}

func (q *recordingGraphQueue) roots() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	roots := make([]string, 0, len(q.requests))
	for _, req := range q.requests {
		roots = append(roots, req.Root.Name+"@"+req.Root.Version)
	}
	return roots
}

func newAuditTestHandler(queue *recordingGraphQueue, lister *stubManifestLister) *RegistryHandler {
	upstream := &domain.Upstream{
		ID:        "up-1",
		TenantID:  "t-1",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	snapshots := service.NewNPMInstallSnapshotService(lister, queue, slog.Default())
	return NewRegistryHandler(nil, nil, &mockUpstreamRepository{upstream: upstream}, slog.Default(), nil, snapshots)
}

func Test_handleAuditBulk_infersRootAndEnqueues(t *testing.T) {
	queue := &recordingGraphQueue{}
	lister := &stubManifestLister{deps: map[string][]string{
		"morgan@1.10.0": {"debug"},
		"debug@2.6.9":   nil,
	}}
	h := newAuditTestHandler(queue, lister)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"morgan":["1.10.0"],"debug":["2.6.9"]}`
	req := httptest.NewRequest(http.MethodPost, "/npm/-/npm/v1/security/advisories/bulk", strings.NewReader(body))
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, "{}", rr.Body.String())

	require.Eventually(t, func() bool {
		return len(queue.roots()) == 1
	}, 2*time.Second, 10*time.Millisecond, "expected one inferred root job")
	assert.Equal(t, []string{"morgan@1.10.0"}, queue.roots())
}

func Test_handleAuditBulk_gzipEncodedBody(t *testing.T) {
	queue := &recordingGraphQueue{}
	lister := &stubManifestLister{deps: map[string][]string{
		"morgan@1.10.0": {"debug"},
		"debug@2.6.9":   nil,
	}}
	h := newAuditTestHandler(queue, lister)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	_, err := gzipWriter.Write([]byte(`{"morgan":["1.10.0"],"debug":["2.6.9"]}`))
	require.NoError(t, err)
	require.NoError(t, gzipWriter.Close())

	req := httptest.NewRequest(http.MethodPost, "/npm/-/npm/v1/security/advisories/bulk", &compressed)
	req.Header.Set("Content-Encoding", "gzip")
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, "{}", rr.Body.String())

	require.Eventually(t, func() bool {
		return len(queue.roots()) == 1
	}, 2*time.Second, 10*time.Millisecond, "expected one inferred root job from gzip payload")
	assert.Equal(t, []string{"morgan@1.10.0"}, queue.roots())
}

func Test_handleAuditBulk_withoutSnapshotService(t *testing.T) {
	h := NewRegistryHandler(nil, nil, &mockUpstreamRepository{}, slog.Default(), nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"morgan":["1.10.0"]}`
	req := httptest.NewRequest(http.MethodPost, "/npm/-/npm/v1/security/advisories/bulk", strings.NewReader(body))
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, "{}", rr.Body.String())
}

func Test_handleAuditBulk_invalidPayload(t *testing.T) {
	h := newAuditTestHandler(&recordingGraphQueue{}, &stubManifestLister{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/npm/-/npm/v1/security/advisories/bulk", strings.NewReader("not-json"))
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func Test_routePost_unknownEndpoint(t *testing.T) {
	h := newAuditTestHandler(&recordingGraphQueue{}, &stubManifestLister{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/npm/-/npm/v1/security/audits/quick", strings.NewReader("{}"))
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}
