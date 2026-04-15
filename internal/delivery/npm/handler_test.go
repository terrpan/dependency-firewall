package npm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

// --- Mock implementations ---

type mockPolicyRepository struct {
	policies []domain.Policy
}

func (m *mockPolicyRepository) GetByID(_ context.Context, _, _ string) (*domain.Policy, error) {
	return nil, domain.ErrPolicyNotFound
}

func (m *mockPolicyRepository) ListByTenant(_ context.Context, _ string) ([]domain.Policy, error) {
	return m.policies, nil
}

func (m *mockPolicyRepository) Create(_ context.Context, _ *domain.Policy) error { return nil }
func (m *mockPolicyRepository) Update(_ context.Context, _ *domain.Policy) error { return nil }
func (m *mockPolicyRepository) Delete(_ context.Context, _, _ string) error      { return nil }

type mockDecisionRepository struct {
	hasRecentAllow bool
}

func (m *mockDecisionRepository) Record(_ context.Context, _ *domain.Decision) error { return nil }

func (m *mockDecisionRepository) GetByArtifact(_ context.Context, _ string, _ domain.ArtifactIdentity) (*domain.Decision, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockDecisionRepository) ListByTenant(_ context.Context, _ string, _, _ int) ([]domain.Decision, error) {
	return nil, nil
}

func (m *mockDecisionRepository) HasRecentAllow(_ context.Context, _ string, _ domain.EcosystemType, _, _ string) (bool, error) {
	return m.hasRecentAllow, nil
}

type mockDecisionCache struct{}

func (m *mockDecisionCache) Get(_ context.Context, _ string, _ domain.ArtifactIdentity) (*domain.Decision, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockDecisionCache) Set(_ context.Context, _ *domain.Decision, _ time.Duration) error {
	return nil
}

func (m *mockDecisionCache) Invalidate(_ context.Context, _ string, _ domain.ArtifactIdentity) error {
	return nil
}

type mockMetadataCache struct{}

func (m *mockMetadataCache) Get(_ context.Context, _ string, _ domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockMetadataCache) Set(_ context.Context, _ string, _ domain.ArtifactIdentity, _ *domain.ArtifactMetadata, _ time.Duration) error {
	return nil
}

type mockEnricher struct{}

func (m *mockEnricher) Enrich(_ context.Context, _ domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	return &domain.ArtifactMetadata{}, nil
}

type mockUpstreamClient struct {
	manifestBody string
	blobBody     string
}

func (m *mockUpstreamClient) GetManifest(_ context.Context, _ domain.Upstream, _ domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	return &port.UpstreamResponse{
		StatusCode:  http.StatusOK,
		ContentType: "application/json",
		Headers:     map[string]string{},
		Body:        io.NopCloser(strings.NewReader(m.manifestBody)),
	}, nil
}

func (m *mockUpstreamClient) GetBlob(_ context.Context, _ domain.Upstream, _ string) (*port.UpstreamResponse, error) {
	return &port.UpstreamResponse{
		StatusCode:  http.StatusOK,
		ContentType: "application/octet-stream",
		Headers:     map[string]string{},
		Body:        io.NopCloser(strings.NewReader(m.blobBody)),
	}, nil
}

func (m *mockUpstreamClient) ResolveTag(_ context.Context, _ domain.Upstream, _ domain.ArtifactIdentity) (string, error) {
	return "", domain.ErrArtifactNotFound
}

type mockUpstreamRepository struct {
	upstream *domain.Upstream
}

func (m *mockUpstreamRepository) GetByID(_ context.Context, _, _ string) (*domain.Upstream, error) {
	return m.upstream, nil
}

func (m *mockUpstreamRepository) GetByEcosystem(_ context.Context, _ string, _ domain.EcosystemType) (*domain.Upstream, error) {
	if m.upstream == nil {
		return nil, domain.ErrUpstreamNotFound
	}
	return m.upstream, nil
}

func (m *mockUpstreamRepository) ListByTenant(_ context.Context, _ string) ([]domain.Upstream, error) {
	if m.upstream == nil {
		return nil, nil
	}
	return []domain.Upstream{*m.upstream}, nil
}

func (m *mockUpstreamRepository) Create(_ context.Context, _ *domain.Upstream) error { return nil }
func (m *mockUpstreamRepository) Update(_ context.Context, _ *domain.Upstream) error { return nil }
func (m *mockUpstreamRepository) Delete(_ context.Context, _, _ string) error        { return nil }

// --- Helpers ---

func newTestHandler(policies []domain.Policy, hasRecentAllow bool) *Handler {
	upstream := &domain.Upstream{
		ID:        "up-1",
		TenantID:  "t-1",
		Name:      "npmjs",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}

	upstreamClient := &mockUpstreamClient{
		manifestBody: `{"name":"express","versions":{}}`,
		blobBody:     "fake-tarball-content",
	}
	upstreamRepo := &mockUpstreamRepository{upstream: upstream}

	proxySvc := service.NewProxyService(
		&mockPolicyRepository{policies: policies},
		&mockDecisionRepository{hasRecentAllow: hasRecentAllow},
		&mockDecisionCache{},
		&mockMetadataCache{},
		&mockEnricher{},
		policy.NewEvaluator(),
		upstreamClient,
		upstreamRepo,
		slog.Default(),
	)

	return NewHandler(proxySvc, upstreamClient, upstreamRepo, slog.Default())
}

func withTenant(r *http.Request) *http.Request {
	tenant := domain.Tenant{ID: "t-1", Name: "test-tenant"}
	ctx := middleware.ContextWithTenant(r.Context(), tenant)
	return r.WithContext(ctx)
}

// --- Tests ---

func Test_handleMetadata_scopedPackage(t *testing.T) {
	h := newTestHandler(nil, false)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/@scope/express", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "express")
}

func Test_handleMetadata_unscopedPackage(t *testing.T) {
	h := newTestHandler(nil, false)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/express", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "express")
}

func Test_handleMetadata_unscopedPackageWithVersion(t *testing.T) {
	h := newTestHandler(nil, false)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/express/4.18.2", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func Test_handleMetadata_denied(t *testing.T) {
	blocklist := []domain.Policy{
		{
			ID:       "p-1",
			TenantID: "t-1",
			Name:     "block-all",
			Type:     domain.PolicyTypeBlocklist,
			Action:   domain.PolicyActionDeny,
			Config:   map[string]any{"packages": []any{"*"}},
			Priority: 1,
			Enabled:  true,
		},
	}
	h := newTestHandler(blocklist, false)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/express", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)

	var resp npmErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "policy violation:")
}

func Test_handleTarball_allowed(t *testing.T) {
	h := newTestHandler(nil, true)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/express/-/express-4.18.2.tgz", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "fake-tarball-content", rr.Body.String())
}

func Test_handleTarball_denied(t *testing.T) {
	h := newTestHandler(nil, false) // hasRecentAllow = false
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/express/-/express-4.18.2.tgz", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)

	var resp npmErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "no allow decision")
}

func Test_handleTarball_scopedPackage(t *testing.T) {
	h := newTestHandler(nil, true)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/@babel/core/-/core-7.23.0.tgz", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "fake-tarball-content", rr.Body.String())
}

func Test_parsePackagePath(t *testing.T) {
	tests := []struct {
		path        string
		wantName    string
		wantVersion string
	}{
		{"express", "express", ""},
		{"express/4.18.2", "express", "4.18.2"},
		{"@scope/name", "@scope/name", ""},
		{"@scope/name/1.0.0", "@scope/name", "1.0.0"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			name, version := parsePackagePath(tc.path)
			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantVersion, version)
		})
	}
}

func Test_parseTarballPath(t *testing.T) {
	tests := []struct {
		path        string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"express/-/express-4.18.2.tgz", "express", "4.18.2", true},
		{"@scope/name/-/name-1.0.0.tgz", "@scope/name", "1.0.0", true},
		{"express/4.18.2", "", "", false},
		{"express/-/express-.tgz", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			name, version, ok := parseTarballPath(tc.path)
			assert.Equal(t, tc.wantOK, ok)
			if ok {
				assert.Equal(t, tc.wantName, name)
				assert.Equal(t, tc.wantVersion, version)
			}
		})
	}
}

func Test_writeNPMError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeNPMError(rr, "something went wrong", http.StatusForbidden)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp npmErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "something went wrong", resp.Error)
}

func Test_emptyPath_returns400(t *testing.T) {
	h := newTestHandler(nil, false)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
