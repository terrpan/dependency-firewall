package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"log/slog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// --- Mock repositories ---

type mockTenantRepo struct {
	mu      sync.RWMutex
	tenants map[string]*domain.Tenant
	nextID  int
}

func newMockTenantRepo() *mockTenantRepo {
	return &mockTenantRepo{tenants: make(map[string]*domain.Tenant)}
}

func (m *mockTenantRepo) Create(_ context.Context, t *domain.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	t.ID = fmt.Sprintf("t-%d", m.nextID)
	m.tenants[t.ID] = t
	return nil
}

func (m *mockTenantRepo) GetByID(_ context.Context, id string) (*domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[id]
	if !ok {
		return nil, domain.ErrTenantNotFound
	}
	return t, nil
}

func (m *mockTenantRepo) List(_ context.Context) ([]domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]domain.Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		result = append(result, *t)
	}
	return result, nil
}

func (m *mockTenantRepo) Update(_ context.Context, t *domain.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[t.ID]; !ok {
		return domain.ErrTenantNotFound
	}
	m.tenants[t.ID] = t
	return nil
}

func (m *mockTenantRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[id]; !ok {
		return domain.ErrTenantNotFound
	}
	delete(m.tenants, id)
	return nil
}

type mockPolicyRepo struct {
	mu       sync.RWMutex
	policies map[string]*domain.Policy // key: tenantID:id
	nextID   int
}

func newMockPolicyRepo() *mockPolicyRepo {
	return &mockPolicyRepo{policies: make(map[string]*domain.Policy)}
}

func (m *mockPolicyRepo) key(tenantID, id string) string {
	return tenantID + ":" + id
}

func (m *mockPolicyRepo) Create(_ context.Context, p *domain.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.ID == "" {
		m.nextID++
		p.ID = fmt.Sprintf("p-%d", m.nextID)
	}
	m.policies[m.key(p.TenantID, p.ID)] = p
	return nil
}

func (m *mockPolicyRepo) GetByID(_ context.Context, tenantID, id string) (*domain.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[m.key(tenantID, id)]
	if !ok {
		return nil, domain.ErrPolicyNotFound
	}
	return p, nil
}

func (m *mockPolicyRepo) ListByTenant(_ context.Context, tenantID string) ([]domain.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Policy
	for _, p := range m.policies {
		if p.TenantID == tenantID {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (m *mockPolicyRepo) Update(_ context.Context, p *domain.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(p.TenantID, p.ID)
	if _, ok := m.policies[k]; !ok {
		return domain.ErrPolicyNotFound
	}
	m.policies[k] = p
	return nil
}

func (m *mockPolicyRepo) Delete(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(tenantID, id)
	if _, ok := m.policies[k]; !ok {
		return domain.ErrPolicyNotFound
	}
	delete(m.policies, k)
	return nil
}

type mockUpstreamRepo struct {
	mu        sync.RWMutex
	upstreams map[string]*domain.Upstream // key: tenantID:id
	nextID    int
}

func newMockUpstreamRepo() *mockUpstreamRepo {
	return &mockUpstreamRepo{upstreams: make(map[string]*domain.Upstream)}
}

func (m *mockUpstreamRepo) key(tenantID, id string) string {
	return tenantID + ":" + id
}

func (m *mockUpstreamRepo) Create(_ context.Context, u *domain.Upstream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	u.ID = fmt.Sprintf("u-%d", m.nextID)
	m.upstreams[m.key(u.TenantID, u.ID)] = u
	return nil
}

func (m *mockUpstreamRepo) GetByID(_ context.Context, tenantID, id string) (*domain.Upstream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.upstreams[m.key(tenantID, id)]
	if !ok {
		return nil, domain.ErrUpstreamNotFound
	}
	return u, nil
}

func (m *mockUpstreamRepo) GetByEcosystem(_ context.Context, tenantID string, eco domain.EcosystemType) (*domain.Upstream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.upstreams {
		if u.TenantID == tenantID && u.Ecosystem == eco {
			return u, nil
		}
	}
	return nil, domain.ErrUpstreamNotFound
}

func (m *mockUpstreamRepo) ListByTenant(_ context.Context, tenantID string) ([]domain.Upstream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Upstream
	for _, u := range m.upstreams {
		if u.TenantID == tenantID {
			result = append(result, *u)
		}
	}
	return result, nil
}

func (m *mockUpstreamRepo) Update(_ context.Context, u *domain.Upstream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(u.TenantID, u.ID)
	if _, ok := m.upstreams[k]; !ok {
		return domain.ErrUpstreamNotFound
	}
	m.upstreams[k] = u
	return nil
}

func (m *mockUpstreamRepo) Delete(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(tenantID, id)
	if _, ok := m.upstreams[k]; !ok {
		return domain.ErrUpstreamNotFound
	}
	delete(m.upstreams, k)
	return nil
}

type mockDecisionRepo struct {
	mu        sync.RWMutex
	decisions []domain.Decision
}

func newMockDecisionRepo() *mockDecisionRepo {
	return &mockDecisionRepo{}
}

func (m *mockDecisionRepo) Record(_ context.Context, d *domain.Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions = append(m.decisions, *d)
	return nil
}

func (m *mockDecisionRepo) GetByArtifact(_ context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.decisions {
		d := &m.decisions[i]
		if d.TenantID == tenantID && d.Artifact == artifact {
			return d, nil
		}
	}
	return nil, domain.ErrArtifactNotFound
}

func (m *mockDecisionRepo) ListByTenant(_ context.Context, tenantID string, limit, offset int) ([]domain.Decision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Decision
	for _, d := range m.decisions {
		if d.TenantID == tenantID {
			result = append(result, d)
		}
	}
	if offset >= len(result) {
		return nil, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

func (m *mockDecisionRepo) HasRecentAllow(_ context.Context, _ string, _ domain.EcosystemType, _, _ string) (bool, error) {
	return false, nil
}

// --- Test helpers ---

func setupTestServer(t *testing.T) (*httptest.Server, *mockTenantRepo, *mockPolicyRepo, *mockUpstreamRepo, *mockDecisionRepo) {
	t.Helper()
	logger := slog.Default()
	tenantRepo := newMockTenantRepo()
	policyRepo := newMockPolicyRepo()
	upstreamRepo := newMockUpstreamRepo()
	decisionRepo := newMockDecisionRepo()

	mux := http.NewServeMux()
	NewTenantHandler(tenantRepo, logger).RegisterRoutes(mux)
	NewPolicyHandler(policyRepo, logger).RegisterRoutes(mux)
	NewUpstreamHandler(upstreamRepo, logger).RegisterRoutes(mux)
	NewEvaluationHandler(decisionRepo, logger).RegisterRoutes(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, tenantRepo, policyRepo, upstreamRepo, decisionRepo
}

func doJSON(t *testing.T, method, url string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req, err := http.NewRequest(method, url, &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func doRaw(t *testing.T, method, url string, body []byte, contentType string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&v))
	return v
}

// --- Tests ---

func Test_TenantCRUD(t *testing.T) {
	srv, _, _, _, _ := setupTestServer(t)

	// Create
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/tenants", map[string]string{"name": "acme"}, nil)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[domain.Tenant](t, resp)
	assert.Equal(t, "acme", created.Name)
	assert.NotEmpty(t, created.ID)

	// Get
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/tenants/"+created.ID, nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	got := decodeJSON[domain.Tenant](t, resp)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "acme", got.Name)

	// List
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/tenants", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]domain.Tenant](t, resp)
	assert.Len(t, list, 1)

	// Update
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/tenants/"+created.ID, map[string]string{"name": "acme-updated"}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	updated := decodeJSON[domain.Tenant](t, resp)
	assert.Equal(t, "acme-updated", updated.Name)

	// Delete
	resp = doJSON(t, http.MethodDelete, srv.URL+"/api/v1/tenants/"+created.ID, nil, nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Not found after delete
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/tenants/"+created.ID, nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func Test_TenantNotFound(t *testing.T) {
	srv, _, _, _, _ := setupTestServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/tenants/nonexistent", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func Test_PolicyCRUD(t *testing.T) {
	srv, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Create
	body := map[string]any{
		"name":   "block-critical",
		"type":   "cvss_threshold",
		"action": "deny",
		"config": map[string]any{"threshold": 9.0},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[domain.Policy](t, resp)
	assert.Equal(t, "block-critical", created.Name)
	assert.Equal(t, "tenant-1", created.TenantID)
	assert.NotEmpty(t, created.ID)

	// Get
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	got := decodeJSON[domain.Policy](t, resp)
	assert.Equal(t, created.ID, got.ID)

	// List
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]domain.Policy](t, resp)
	assert.Len(t, list, 1)

	// Update
	body["name"] = "block-critical-updated"
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/policies/"+created.ID, body, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	updated := decodeJSON[domain.Policy](t, resp)
	assert.Equal(t, "block-critical-updated", updated.Name)

	// Delete
	resp = doJSON(t, http.MethodDelete, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Not found after delete
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func Test_PolicyImportYAML(t *testing.T) {
	srv, _, policyRepo, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-import"}

	yamlBody := []byte(`
tenant_id: "ignored-id"
policies:
  - name: block-high-cvss
    type: cvss_threshold
    action: deny
    config:
      threshold: 7.5
  - name: require-age
    type: minimum_age
    action: deny
    config:
      days: 30
`)
	resp := doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", yamlBody, "application/x-yaml", headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON[map[string]int](t, resp)
	assert.Equal(t, 2, result["imported"])

	// Verify policies were created with the header tenant ID, not the YAML one.
	policies, err := policyRepo.ListByTenant(context.Background(), "tenant-import")
	require.NoError(t, err)
	assert.Len(t, policies, 2)
	for _, p := range policies {
		assert.Equal(t, "tenant-import", p.TenantID)
	}
}

func Test_UpstreamCRUD(t *testing.T) {
	srv, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Create
	body := map[string]string{
		"name":      "docker-hub",
		"ecosystem": "oci",
		"base_url":  "https://registry-1.docker.io",
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[domain.Upstream](t, resp)
	assert.Equal(t, "docker-hub", created.Name)
	assert.Equal(t, "tenant-1", created.TenantID)
	assert.NotEmpty(t, created.ID)

	// Get
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	got := decodeJSON[domain.Upstream](t, resp)
	assert.Equal(t, created.ID, got.ID)

	// List
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]domain.Upstream](t, resp)
	assert.Len(t, list, 1)

	// Update
	body["name"] = "docker-hub-updated"
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/upstreams/"+created.ID, body, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	updated := decodeJSON[domain.Upstream](t, resp)
	assert.Equal(t, "docker-hub-updated", updated.Name)

	// Delete
	resp = doJSON(t, http.MethodDelete, srv.URL+"/api/v1/upstreams/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Not found after delete
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func Test_EvaluationList(t *testing.T) {
	srv, _, _, _, decisionRepo := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Seed some decisions.
	for i := range 3 {
		_ = decisionRepo.Record(context.Background(), &domain.Decision{
			ID:       fmt.Sprintf("d-%d", i),
			TenantID: "tenant-1",
			Outcome:  domain.DecisionAllow,
		})
	}
	// Add a decision for a different tenant.
	_ = decisionRepo.Record(context.Background(), &domain.Decision{
		ID:       "d-other",
		TenantID: "tenant-2",
		Outcome:  domain.DecisionDeny,
	})

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/evaluations", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]domain.Decision](t, resp)
	assert.Len(t, list, 3)

	// With limit and offset.
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/evaluations?limit=2&offset=1", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list = decodeJSON[[]domain.Decision](t, resp)
	assert.Len(t, list, 2)
}

func Test_MissingTenantIDHeader(t *testing.T) {
	srv, _, _, _, _ := setupTestServer(t)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"list policies", http.MethodGet, "/api/v1/policies"},
		{"create policy", http.MethodPost, "/api/v1/policies"},
		{"list upstreams", http.MethodGet, "/api/v1/upstreams"},
		{"create upstream", http.MethodPost, "/api/v1/upstreams"},
		{"list evaluations", http.MethodGet, "/api/v1/evaluations"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, tc.method, srv.URL+tc.path, map[string]string{"name": "x"}, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			body := decodeJSON[map[string]string](t, resp)
			assert.Contains(t, body["error"], "X-Tenant-ID")
		})
	}
}
