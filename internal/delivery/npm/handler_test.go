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

func ptrInt(v int) *int { return &v }

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

func (m *mockPolicyRepository) ListVersions(_ context.Context, _, _ string, _ int) ([]domain.PolicyVersion, error) {
	return nil, domain.ErrPolicyNotFound
}

func (m *mockPolicyRepository) RollbackToVersion(_ context.Context, _, _ string, _ int) (*domain.Policy, error) {
	return nil, domain.ErrPolicyNotFound
}

func (m *mockPolicyRepository) Create(_ context.Context, _ *domain.Policy) error    { return nil }
func (m *mockPolicyRepository) Update(_ context.Context, _ *domain.Policy) error    { return nil }
func (m *mockPolicyRepository) Delete(_ context.Context, _, _ string, _ bool) error { return nil }

type mockDecisionRepository struct {
	hasRecentAllow bool
}

func (m *mockDecisionRepository) Record(_ context.Context, _ *domain.Decision) error { return nil }

func (m *mockDecisionRepository) GetByArtifact(_ context.Context, _ string, _ domain.ArtifactIdentity) (*domain.Decision, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockDecisionRepository) ListByTenant(_ context.Context, _ string, _, _ int, _ string) ([]domain.Decision, error) {
	return nil, nil
}

func (m *mockDecisionRepository) HasRecentAllow(_ context.Context, _ string, _ domain.EcosystemType, _, _ string) (bool, error) {
	return m.hasRecentAllow, nil
}

type mockDecisionCache struct{}

func (m *mockDecisionCache) Get(_ context.Context, _ string, _ domain.ArtifactIdentity, _ string) (*domain.Decision, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockDecisionCache) Set(_ context.Context, _ *domain.Decision, _ time.Duration) error {
	return nil
}

func (m *mockDecisionCache) Invalidate(_ context.Context, _ string, _ domain.ArtifactIdentity) error {
	return nil
}

func (m *mockDecisionCache) InvalidateTenant(_ context.Context, _ string) error {
	return nil
}

type mockMetadataCache struct{}

func (m *mockMetadataCache) Get(_ context.Context, _ string, _ domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockMetadataCache) Set(_ context.Context, _ string, _ domain.ArtifactIdentity, _ *domain.ArtifactMetadata, _ time.Duration) error {
	return nil
}

func (m *mockMetadataCache) InvalidateTenant(_ context.Context, _ string) error {
	return nil
}

type mockEnricher struct{}

func (m *mockEnricher) Enrich(_ context.Context, _ domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	return &domain.ArtifactMetadata{}, nil
}

// mockAgeEnricher returns old publish dates for versioned requests, nil for unversioned.
type mockAgeEnricher struct{}

func (m *mockAgeEnricher) Enrich(_ context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	if artifact.Version == "" {
		return &domain.ArtifactMetadata{}, nil
	}
	old := time.Now().AddDate(-3, 0, 0) // 3 years ago
	return &domain.ArtifactMetadata{PublishedAt: &old}, nil
}

type mockUpstreamClient struct {
	manifestBody string
	blobBody     string
}

func (m *mockUpstreamClient) FetchMetadata(_ context.Context, _ domain.Upstream, _ domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	return &port.UpstreamResponse{
		StatusCode:  http.StatusOK,
		ContentType: "application/json",
		Headers:     map[string]string{},
		Body:        io.NopCloser(strings.NewReader(m.manifestBody)),
	}, nil
}

func (m *mockUpstreamClient) FetchContent(_ context.Context, _ domain.Upstream, _ string) (*port.UpstreamResponse, error) {
	return &port.UpstreamResponse{
		StatusCode:  http.StatusOK,
		ContentType: "application/octet-stream",
		Headers:     map[string]string{},
		Body:        io.NopCloser(strings.NewReader(m.blobBody)),
	}, nil
}

func (m *mockUpstreamClient) ResolveReference(_ context.Context, _ domain.Upstream, _ domain.ArtifactIdentity) (string, error) {
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

type mockAuditRecorder struct {
	events []domain.AuditEvent
}

func (m *mockAuditRecorder) Record(_ context.Context, event *domain.AuditEvent) error {
	m.events = append(m.events, *event)
	return nil
}

// --- Helpers ---

func newTestHandler(policies []domain.Policy, hasRecentAllow bool) *RegistryHandler {
	return newTestHandlerWithEnricher(policies, hasRecentAllow, &mockEnricher{})
}

func newTestHandlerWithEnricher(policies []domain.Policy, hasRecentAllow bool, enricher port.Enricher) *RegistryHandler {
	return newTestHandlerWithEnricherAndAudit(policies, hasRecentAllow, enricher, nil)
}

func newTestHandlerWithEnricherAndAudit(
	policies []domain.Policy,
	hasRecentAllow bool,
	enricher port.Enricher,
	auditSvc *service.AuditService,
) *RegistryHandler {
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

	enrichmentService := service.NewEnrichmentService(enricher, &mockMetadataCache{}, slog.Default())
	accessSvc := service.NewAccessService(
		&mockPolicyRepository{policies: policies},
		&mockDecisionRepository{hasRecentAllow: hasRecentAllow},
		&mockDecisionCache{},
		enrichmentService,
		policy.NewEvaluator(),
		upstreamClient,
		upstreamRepo,
		slog.Default(),
		auditSvc,
	)

	return NewRegistryHandler(accessSvc, upstreamClient, upstreamRepo, slog.Default(), auditSvc, nil)
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

func Test_handleMetadata_unversionedPackageLogsForwardedNotAllowed(t *testing.T) {
	auditRecorder := &mockAuditRecorder{}
	auditSvc := service.NewAuditService(
		auditRecorder,
		nil,
		slog.Default(),
		true,
		domain.AuditFailureModeFailOpen,
		domain.AuditDetailLevelSummary,
	)
	h := newTestHandlerWithEnricherAndAudit(nil, false, &mockEnricher{}, auditSvc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/express", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var sawForwarded bool
	for _, event := range auditRecorder.events {
		assert.NotEqual(t, domain.AuditEventRequestAllowed, event.EventType)
		assert.NotEqual(t, domain.AuditEventDecisionComputed, event.EventType)
		assert.NotEqual(t, domain.AuditEventDecisionPersisted, event.EventType)
		if event.EventType == domain.AuditEventRequestForwarded {
			sawForwarded = true
			assert.Equal(t, "npm metadata request forwarded", event.Message)
			assert.Equal(t, "metadata", event.Payload["operation"])
			assert.Contains(t, event.Payload["reason"], "bare npm packument")
			assert.Empty(t, event.Outcome)
		}
	}
	assert.True(t, sawForwarded, "expected unversioned metadata request to emit request_forwarded")
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
			Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{""}},
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
	h := newTestHandler(nil, false) // no policies = default allow
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
	blocklist := []domain.Policy{
		{
			ID:       "p-1",
			TenantID: "t-1",
			Name:     "block-all",
			Type:     domain.PolicyTypeBlocklist,
			Action:   domain.PolicyActionDeny,
			Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{""}},
			Priority: 1,
			Enabled:  true,
		},
	}
	h := newTestHandler(blocklist, false)
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
	assert.Contains(t, resp.Error, "policy violation:")
}

func Test_handleTarball_scopedPackage(t *testing.T) {
	h := newTestHandler(nil, false) // no policies = default allow
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

// Regression test: metadata allow (no version) must not bypass tarball deny (with version).
// This reproduces the bug where npm metadata requests allowed versionless lookups,
// and tarball downloads skipped policy evaluation entirely.
func Test_handleTarball_metadataAllowDoesNotBypassTarballDeny(t *testing.T) {
	maxAgePolicies := []domain.Policy{
		{
			ID:       "p-age",
			TenantID: "t-1",
			Name:     "block-old",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365)},
			Priority: 10,
			Enabled:  true,
		},
	}
	h := newTestHandlerWithEnricher(maxAgePolicies, true, &mockAgeEnricher{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Step 1: metadata request (no version) — should be allowed since age conditions
	// skip without a publish date on unversioned requests.
	metaReq := httptest.NewRequest(http.MethodGet, "/npm/express", nil)
	metaReq = withTenant(metaReq)
	metaRR := httptest.NewRecorder()
	mux.ServeHTTP(metaRR, metaReq)
	assert.Equal(t, http.StatusOK, metaRR.Code, "metadata request should be allowed")

	// Step 2: tarball request (with version) — must be denied because the enricher
	// returns an old publish date and the maximum_age policy should block it.
	tarballReq := httptest.NewRequest(http.MethodGet, "/npm/express/-/express-4.19.1.tgz", nil)
	tarballReq = withTenant(tarballReq)
	tarballRR := httptest.NewRecorder()
	mux.ServeHTTP(tarballRR, tarballReq)

	assert.Equal(t, http.StatusForbidden, tarballRR.Code, "tarball request should be denied by maximum_age policy")

	var resp npmErrorResponse
	err := json.NewDecoder(tarballRR.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "policy violation:")
	assert.Contains(t, resp.Error, "maximum allowed is 365 days")
}

func Test_handleMetadata_unversionedRequestSkipsLicenseAllowlistButTarballStillDenies(t *testing.T) {
	licensePolicies := []domain.Policy{
		{
			ID:            "p-license",
			TenantID:      "t-1",
			Name:          "allow-approved-licenses",
			Type:          domain.PolicyTypeLicenseAllowlist,
			Action:        domain.PolicyActionDeny,
			SchemaVersion: 1,
			Config:        &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT"}},
			Priority:      10,
			Enabled:       true,
		},
	}
	h := newTestHandlerWithEnricher(licensePolicies, false, &mockEnricher{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	metaReq := httptest.NewRequest(http.MethodGet, "/npm/react", nil)
	metaReq = withTenant(metaReq)
	metaRR := httptest.NewRecorder()
	mux.ServeHTTP(metaRR, metaReq)
	assert.Equal(t, http.StatusOK, metaRR.Code, "metadata request should be allowed so npm can resolve a concrete version")

	tarballReq := httptest.NewRequest(http.MethodGet, "/npm/react/-/react-19.2.0.tgz", nil)
	tarballReq = withTenant(tarballReq)
	tarballRR := httptest.NewRecorder()
	mux.ServeHTTP(tarballRR, tarballReq)
	assert.Equal(t, http.StatusForbidden, tarballRR.Code, "versioned tarball request should still fail closed when no license is declared")

	var resp npmErrorResponse
	err := json.NewDecoder(tarballRR.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "does not declare a license")
}

func Test_handleMetadata_rewritesTarballURLsToFirewall(t *testing.T) {
	upstream := &domain.Upstream{
		ID:        "up-1",
		TenantID:  "t-1",
		Name:      "npmjs",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	upstreamClient := &mockUpstreamClient{
		manifestBody: `{
			"name":"express",
			"dist-tags":{"latest":"4.18.2"},
			"versions":{
				"4.18.2":{
					"name":"express",
					"version":"4.18.2",
					"dist":{"tarball":"https://registry.npmjs.org/express/-/express-4.18.2.tgz"}
				}
			}
		}`,
		blobBody: "fake-tarball-content",
	}
	upstreamRepo := &mockUpstreamRepository{upstream: upstream}
	enrichmentService := service.NewEnrichmentService(&mockEnricher{}, &mockMetadataCache{}, slog.Default())
	accessSvc := service.NewAccessService(
		&mockPolicyRepository{},
		&mockDecisionRepository{},
		&mockDecisionCache{},
		enrichmentService,
		policy.NewEvaluator(),
		upstreamClient,
		upstreamRepo,
		slog.Default(),
		nil,
	)

	h := NewRegistryHandler(accessSvc, upstreamClient, upstreamRepo, slog.Default(), nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/npm/express", nil)
	req = withTenant(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var payload struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	err := json.NewDecoder(rr.Body).Decode(&payload)
	require.NoError(t, err)
	assert.Equal(
		t,
		"http://example.com/npm/t/t-1/u/up-1/express/-/express-4.18.2.tgz",
		payload.Versions["4.18.2"].Dist.Tarball,
	)
}
