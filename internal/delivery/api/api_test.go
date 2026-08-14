package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

func ptrFloat64(v float64) *float64 { return &v }

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
	mu                    sync.RWMutex
	policies              map[string]*domain.Policy // key: tenantID:id
	versions              map[string][]domain.PolicyVersion
	nextID                int
	getErr                error
	listErr               error
	deleteErr             error
	deleteErrWithoutForce error
	lastDeleteForce       bool
}

func newMockPolicyRepo() *mockPolicyRepo {
	return &mockPolicyRepo{
		policies: make(map[string]*domain.Policy),
		versions: make(map[string][]domain.PolicyVersion),
	}
}

func (m *mockPolicyRepo) key(tenantID, id string) string {
	return tenantID + ":" + id
}

func (m *mockPolicyRepo) Create(_ context.Context, p *domain.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.policies {
		if existing.TenantID == p.TenantID && existing.Name == p.Name {
			return domain.ErrPolicyNameConflict
		}
	}
	if p.ID == "" {
		m.nextID++
		p.ID = fmt.Sprintf("p-%d", m.nextID)
	}
	if p.Version == 0 {
		p.Version = 1
	}
	m.policies[m.key(p.TenantID, p.ID)] = p
	m.recordVersionLocked(p)
	return nil
}

func (m *mockPolicyRepo) GetByID(_ context.Context, tenantID, id string) (*domain.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	p, ok := m.policies[m.key(tenantID, id)]
	if !ok {
		return nil, domain.ErrPolicyNotFound
	}
	return p, nil
}

func (m *mockPolicyRepo) ListByTenant(_ context.Context, tenantID string) ([]domain.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.listErr != nil {
		return nil, m.listErr
	}
	var result []domain.Policy
	for _, p := range m.policies {
		if p.TenantID == tenantID {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (m *mockPolicyRepo) ListVersions(
	_ context.Context,
	tenantID, policyID string,
	limit int,
) ([]domain.PolicyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.policies[m.key(tenantID, policyID)]; !ok {
		return nil, domain.ErrPolicyNotFound
	}
	versions := append([]domain.PolicyVersion(nil), m.versions[policyID]...)
	if limit > 0 && len(versions) > limit {
		versions = versions[:limit]
	}
	return versions, nil
}

func (m *mockPolicyRepo) Update(_ context.Context, p *domain.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.policies {
		if existing.TenantID == p.TenantID && existing.Name == p.Name && existing.ID != p.ID {
			return domain.ErrPolicyNameConflict
		}
	}
	k := m.key(p.TenantID, p.ID)
	existing, ok := m.policies[k]
	if !ok {
		return domain.ErrPolicyNotFound
	}
	p.Version = existing.Version + 1
	m.policies[k] = p
	m.recordVersionLocked(p)
	return nil
}

func (m *mockPolicyRepo) RollbackToVersion(
	_ context.Context,
	tenantID, policyID string,
	version int,
) (*domain.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.policies[m.key(tenantID, policyID)]
	if !ok {
		return nil, domain.ErrPolicyNotFound
	}
	var snapshot *domain.PolicyVersion
	for i := range m.versions[policyID] {
		if m.versions[policyID][i].Version == version {
			snapshot = &m.versions[policyID][i]
			break
		}
	}
	if snapshot == nil {
		return nil, domain.ErrPolicyVersionNotFound
	}

	updated := *current
	updated.Name = snapshot.Name
	updated.Type = snapshot.Type
	updated.Action = snapshot.Action
	updated.SchemaVersion = snapshot.SchemaVersion
	updated.Config = snapshot.Config
	updated.Priority = snapshot.Priority
	updated.Enabled = snapshot.Enabled
	updated.Version++
	m.policies[m.key(tenantID, policyID)] = &updated
	m.recordVersionLocked(&updated)

	copyPolicy := updated
	return &copyPolicy, nil
}

func (m *mockPolicyRepo) Delete(_ context.Context, tenantID, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastDeleteForce = force
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if !force && m.deleteErrWithoutForce != nil {
		return m.deleteErrWithoutForce
	}
	k := m.key(tenantID, id)
	if _, ok := m.policies[k]; !ok {
		return domain.ErrPolicyNotFound
	}
	delete(m.policies, k)
	delete(m.versions, id)
	return nil
}

func (m *mockPolicyRepo) recordVersionLocked(policy *domain.Policy) {
	version := domain.PolicyVersion{
		TenantID:       policy.TenantID,
		PolicyID:       policy.ID,
		OrganizationID: policy.OrganizationID,
		ScopeKind:      policy.ScopeKind,
		WaiverMode:     policy.WaiverMode,
		Version:        policy.Version,
		UpstreamID:     policy.UpstreamID,
		Name:           policy.Name,
		Type:           policy.Type,
		Action:         policy.Action,
		SchemaVersion:  policy.SchemaVersion,
		Config:         policy.Config,
		Target:         policy.Target,
		Priority:       policy.Priority,
		Enabled:        policy.Enabled,
		CreatedAt:      time.Now(),
	}
	history := append([]domain.PolicyVersion{version}, m.versions[policy.ID]...)
	if len(history) > domain.MaxRetainedPolicyVersions {
		history = history[:domain.MaxRetainedPolicyVersions]
	}
	m.versions[policy.ID] = history
}

type mockUpstreamRepo struct {
	mu        sync.RWMutex
	upstreams map[string]*domain.Upstream // key: tenantID:id
	nextID    int
	deleteErr error
}

type mockDecisionCache struct {
	mu                  sync.Mutex
	invalidatedTenants  []string
	invalidateTenantErr error
}

type mockMetadataCache struct {
	mu                  sync.Mutex
	invalidatedTenants  []string
	invalidateTenantErr error
}

func (m *mockDecisionCache) Get(
	_ context.Context,
	_ string,
	_ domain.ArtifactIdentity,
	_ string,
) (*domain.Decision, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockDecisionCache) Set(_ context.Context, _ *domain.Decision, _ time.Duration) error {
	return nil
}

func (m *mockDecisionCache) Invalidate(_ context.Context, _ string, _ domain.ArtifactIdentity) error {
	return nil
}

func (m *mockDecisionCache) InvalidateTenant(_ context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invalidateTenantErr != nil {
		return m.invalidateTenantErr
	}
	m.invalidatedTenants = append(m.invalidatedTenants, tenantID)
	return nil
}

func (m *mockMetadataCache) Get(
	_ context.Context,
	_ string,
	_ domain.ArtifactIdentity,
) (*domain.ArtifactMetadata, error) {
	return nil, domain.ErrCacheMiss
}

func (m *mockMetadataCache) Set(
	_ context.Context,
	_ string,
	_ domain.ArtifactIdentity,
	_ *domain.ArtifactMetadata,
	_ time.Duration,
) error {
	return nil
}

func (m *mockMetadataCache) InvalidateTenant(_ context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invalidateTenantErr != nil {
		return m.invalidateTenantErr
	}
	m.invalidatedTenants = append(m.invalidatedTenants, tenantID)
	return nil
}

type mockPolicyRevisionRepo struct{}

func (m *mockPolicyRevisionRepo) Create(_ context.Context, _ *domain.PolicySetRevision) error {
	return nil
}

func newMockUpstreamRepo() *mockUpstreamRepo {
	return &mockUpstreamRepo{upstreams: make(map[string]*domain.Upstream)}
}

func (m *mockUpstreamRepo) key(tenantID, id string) string {
	return tenantID + ":" + id
}

func (m *mockUpstreamRepo) validateUpstreamLocked(candidate *domain.Upstream) error {
	for _, upstream := range m.upstreams {
		if upstream.TenantID != candidate.TenantID || upstream.ID == candidate.ID {
			continue
		}
		if upstream.Name == candidate.Name {
			return domain.ErrUpstreamNameConflict
		}
		if upstream.Ecosystem == candidate.Ecosystem && upstream.BaseURL == candidate.BaseURL {
			return domain.ErrUpstreamRegistryConflict
		}
	}
	return nil
}

func (m *mockUpstreamRepo) Create(_ context.Context, u *domain.Upstream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateUpstreamLocked(u); err != nil {
		return err
	}
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

func (m *mockUpstreamRepo) GetByEcosystem(
	_ context.Context,
	tenantID string,
	eco domain.EcosystemType,
) (*domain.Upstream, error) {
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
	existing, ok := m.upstreams[k]
	if !ok {
		return domain.ErrUpstreamNotFound
	}
	if err := m.validateUpstreamLocked(u); err != nil {
		return err
	}
	if u.Auth == nil {
		u.Auth = existing.Auth
	} else if !u.Auth.Configured() {
		u.Auth = nil
	}
	m.upstreams[k] = u
	return nil
}

func (m *mockUpstreamRepo) Delete(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
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

type mockAuditRepo struct {
	mu     sync.RWMutex
	events []domain.AuditEvent
}

func newMockDecisionRepo() *mockDecisionRepo {
	return &mockDecisionRepo{}
}

func newMockAuditRepo() *mockAuditRepo {
	return &mockAuditRepo{}
}

func (m *mockDecisionRepo) Record(_ context.Context, d *domain.Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions = append(m.decisions, *d)
	return nil
}

func (m *mockDecisionRepo) GetByArtifact(
	_ context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.Decision, error) {
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

func (m *mockDecisionRepo) ListByTenant(
	_ context.Context,
	tenantID string,
	limit, offset int,
	search string,
) ([]domain.Decision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Decision
	for _, d := range m.decisions {
		if d.TenantID == tenantID && matchesDecisionArtifactSearch(d, search) {
			result = append(result, d)
		}
	}
	if offset >= len(result) {
		return nil, nil
	}
	end := min(offset+limit, len(result))
	return result[offset:end], nil
}

func matchesDecisionArtifactSearch(decision domain.Decision, search string) bool {
	search = strings.TrimSpace(strings.ToLower(search))
	if search == "" {
		return true
	}

	fields := []string{
		decision.Artifact.Namespace,
		decision.Artifact.Name,
		decision.Artifact.Version,
		decision.Artifact.Digest,
	}
	if decision.Artifact.Namespace != "" && decision.Artifact.Name != "" {
		fields = append(fields, decision.Artifact.Namespace+"/"+decision.Artifact.Name)
	}

	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}

	return false
}

func (m *mockDecisionRepo) HasRecentAllow(
	_ context.Context,
	_ string,
	_ domain.EcosystemType,
	_, _ string,
) (bool, error) {
	return false, nil
}

func (m *mockAuditRepo) ListByTenant(_ context.Context, filter domain.AuditEventFilter) ([]domain.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []domain.AuditEvent
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	for _, event := range m.events {
		if event.TenantID != filter.TenantID {
			continue
		}
		if filter.EventType != "" && event.EventType != filter.EventType {
			continue
		}
		if filter.Outcome != "" && event.Outcome != filter.Outcome {
			continue
		}
		if filter.CorrelationID != "" && event.CorrelationID != filter.CorrelationID {
			continue
		}
		if filter.PolicyID != "" && event.PolicyID != filter.PolicyID {
			continue
		}
		if filter.Source != "" && event.Source != filter.Source {
			continue
		}
		if filter.Since != nil && event.CreatedAt.Before(*filter.Since) {
			continue
		}
		if filter.Until != nil && event.CreatedAt.After(*filter.Until) {
			continue
		}
		if search != "" && !matchesAuditSearch(event, search) {
			continue
		}
		result = append(result, event)
	}
	if filter.Offset >= len(result) {
		return nil, nil
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	end := min(filter.Offset+limit, len(result))
	return result[filter.Offset:end], nil
}

func matchesAuditSearch(event domain.AuditEvent, search string) bool {
	fields := []string{
		string(event.EventType),
		event.Source,
		event.Message,
		event.CorrelationID,
		event.PolicyID,
		event.UpstreamID,
		event.Artifact.Namespace,
		event.Artifact.Name,
		event.Artifact.Version,
		event.Artifact.Digest,
	}
	if event.Artifact.Namespace != "" && event.Artifact.Name != "" {
		fields = append(fields, event.Artifact.Namespace+"/"+event.Artifact.Name)
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}

// --- Test helpers ---

func setupTestServer(
	t *testing.T,
) (*httptest.Server, *mockTenantRepo, *mockPolicyRepo, *mockUpstreamRepo, *mockDecisionRepo, *mockDecisionCache) {
	srv, tenantRepo, policyRepo, upstreamRepo, decisionRepo, decisionCache, _ := setupTestServerWithCaches(t)
	return srv, tenantRepo, policyRepo, upstreamRepo, decisionRepo, decisionCache
}

func setupTestServerWithCaches(
	t *testing.T,
) (*httptest.Server, *mockTenantRepo, *mockPolicyRepo, *mockUpstreamRepo, *mockDecisionRepo, *mockDecisionCache, *mockMetadataCache) {
	t.Helper()
	logger := slog.Default()
	tenantRepo := newMockTenantRepo()
	policyRepo := newMockPolicyRepo()
	upstreamRepo := newMockUpstreamRepo()
	decisionRepo := newMockDecisionRepo()
	auditRepo := newMockAuditRepo()
	decisionCache := &mockDecisionCache{}
	metadataCache := &mockMetadataCache{}

	mux := http.NewServeMux()
	controlPlaneAPI := NewControlPlaneAPI(mux, "test")
	healthSvc := service.NewHealthService(
		"test-firewall", "1.0.0", "abc123", "2024-01-01T00:00:00Z",
		&stubHealthChecker{},
		&stubHealthChecker{},
		logger,
	)
	NewHealthHandler(healthSvc, logger).RegisterHumaRoutes(controlPlaneAPI)
	NewTenantHandler(service.NewTenantService(tenantRepo), logger).RegisterHumaRoutes(controlPlaneAPI)
	NewPolicyHandler(
		service.NewPolicyService(policyRepo, &mockPolicyRevisionRepo{}, decisionCache, upstreamRepo),
		logger,
	).RegisterHumaRoutes(controlPlaneAPI)
	NewCacheHandler(service.NewCacheService(decisionCache, metadataCache), logger).RegisterHumaRoutes(controlPlaneAPI)
	NewUpstreamHandler(service.NewUpstreamService(upstreamRepo, policyRepo), logger).RegisterHumaRoutes(controlPlaneAPI)
	NewEvaluationHandler(service.NewEvaluationService(decisionRepo), logger).RegisterHumaRoutes(controlPlaneAPI)
	NewAuditHandler(
		service.NewAuditService(
			nil,
			auditRepo,
			logger,
			true,
			domain.AuditFailureModeFailClosed,
			domain.AuditDetailLevelSummary,
		),
		logger,
	).RegisterHumaRoutes(controlPlaneAPI)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, tenantRepo, policyRepo, upstreamRepo, decisionRepo, decisionCache, metadataCache
}

func setupAuditTestServer(t *testing.T) (*httptest.Server, *mockAuditRepo) {
	t.Helper()
	logger := slog.Default()
	auditRepo := newMockAuditRepo()

	mux := http.NewServeMux()
	controlPlaneAPI := NewControlPlaneAPI(mux, "test")
	NewAuditHandler(
		service.NewAuditService(
			nil,
			auditRepo,
			logger,
			true,
			domain.AuditFailureModeFailClosed,
			domain.AuditDetailLevelSummary,
		),
		logger,
	).
		RegisterHumaRoutes(controlPlaneAPI)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, auditRepo
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

func doRaw(
	t *testing.T,
	method, url string,
	body []byte,
	contentType string,
	headers map[string]string,
) *http.Response {
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

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

func decodeJSONBytes[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(body, &v))
	return v
}

func decodeBodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	require.NoError(t, err)
	return string(body)
}

// --- Tests ---

func Test_TenantCRUD(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)

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
	resp = doJSON(
		t,
		http.MethodPut,
		srv.URL+"/api/v1/tenants/"+created.ID,
		map[string]string{"name": "acme-updated"},
		nil,
	)
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
	srv, _, _, _, _, _ := setupTestServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/tenants/nonexistent", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func Test_TenantValidation(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/tenants", map[string]string{"name": "   "}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `field "name" is required`)

	resp = doRaw(
		t,
		http.MethodPost,
		srv.URL+"/api/v1/tenants",
		[]byte(`{"name":"acme","slug":"acme"}`),
		"application/json",
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Equal(t, `invalid JSON: unknown field "slug"`, body["error"])

	resp = doRaw(
		t,
		http.MethodPost,
		srv.URL+"/api/v1/tenants",
		[]byte(`{"name":"acme"} trailing`),
		"application/json",
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "invalid JSON: invalid character 't' after top-level value", body["error"])
}

func Test_ControlPlaneDocsAndOpenAPI(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+controlPlaneOpenAPIPath+".json", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/openapi+json", resp.Header.Get("Content-Type"))

	spec := decodeJSON[map[string]any](t, resp)
	paths, ok := spec["paths"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, paths, "/healthz")
	assert.Contains(t, paths, "/api/v1/tenants")
	assert.Contains(t, paths, "/api/v1/tenants/{id}")
	assert.Contains(t, paths, "/api/v1/upstreams")
	assert.Contains(t, paths, "/api/v1/upstreams/{id}")
	assert.Contains(t, paths, "/api/v1/policies")
	assert.Contains(t, paths, "/api/v1/policies/{id}")
	assert.Contains(t, paths, "/api/v1/policies/{id}/versions")
	assert.Contains(t, paths, "/api/v1/policies/{id}/rollback")
	assert.Contains(t, paths, "/api/v1/policy-types")
	assert.Contains(t, paths, "/api/v1/policies/import")
	assert.Contains(t, paths, "/api/v1/evaluations")
	assert.Contains(t, paths, "/api/v1/audit/events")
	assert.Contains(t, paths, "/api/v1/cache/decisions")
	assert.Contains(t, paths, "/api/v1/cache/metadata")
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/policies"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/policies/{id}"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/policies/{id}/versions"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/policies/{id}/rollback"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/tenants"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/tenants/{id}"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/upstreams"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/upstreams/{id}"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/policy-types"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/policies/import"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/evaluations"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/audit/events"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/cache/decisions"]), `"422"`)
	assert.NotContains(t, encodeJSON(t, paths["/api/v1/cache/metadata"]), `"422"`)
	for _, route := range []struct {
		path   string
		method string
	}{
		{"/api/v1/tenants", "get"},
		{"/api/v1/tenants/{id}", "get"},
		{"/api/v1/upstreams", "get"},
		{"/api/v1/upstreams/{id}", "get"},
		{"/api/v1/policies", "get"},
		{"/api/v1/policies/{id}", "get"},
		{"/api/v1/policies/{id}/versions", "get"},
		{"/api/v1/policy-types", "get"},
		{"/api/v1/evaluations", "get"},
		{"/api/v1/audit/events", "get"},
	} {
		assertOpenAPIResponseStatus(t, paths, route.path, route.method, statusClientClosedRequest)
		assertOpenAPIResponseStatus(t, paths, route.path, route.method, http.StatusGatewayTimeout)
	}
	for _, route := range []struct {
		path   string
		method string
	}{
		{"/api/v1/tenants", "post"},
		{"/api/v1/tenants/{id}", "put"},
		{"/api/v1/tenants/{id}", "delete"},
		{"/api/v1/upstreams", "post"},
		{"/api/v1/upstreams/{id}", "put"},
		{"/api/v1/upstreams/{id}", "delete"},
		{"/api/v1/policies", "post"},
		{"/api/v1/policies/{id}", "put"},
		{"/api/v1/policies/{id}", "delete"},
		{"/api/v1/policies/{id}/rollback", "post"},
		{"/api/v1/policies/import", "post"},
		{"/api/v1/cache/decisions", "delete"},
		{"/api/v1/cache/metadata", "delete"},
	} {
		assertOpenAPIResponseStatus(t, paths, route.path, route.method, statusClientClosedRequest)
		assertOpenAPIResponseStatusAbsent(t, paths, route.path, route.method, http.StatusGatewayTimeout)
	}
	assertOpenAPIDescription(t, paths, "/healthz", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/tenants", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/tenants", "post")
	assertOpenAPIDescription(t, paths, "/api/v1/tenants/{id}", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/tenants/{id}", "put")
	assertOpenAPIDescription(t, paths, "/api/v1/tenants/{id}", "delete")
	assertOpenAPIDescription(t, paths, "/api/v1/upstreams", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/upstreams", "post")
	assertOpenAPIDescription(t, paths, "/api/v1/upstreams/{id}", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/upstreams/{id}", "put")
	assertOpenAPIDescription(t, paths, "/api/v1/upstreams/{id}", "delete")
	assertOpenAPIDescription(t, paths, "/api/v1/policies", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/policies", "post")
	assertOpenAPIDescription(t, paths, "/api/v1/policies/{id}", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/policies/{id}", "put")
	assertOpenAPIDescription(t, paths, "/api/v1/policies/{id}", "delete")
	assertOpenAPIDescription(t, paths, "/api/v1/policies/{id}/versions", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/policies/{id}/rollback", "post")
	assertOpenAPIDescription(t, paths, "/api/v1/policy-types", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/policies/import", "post")
	assertOpenAPIDescription(t, paths, "/api/v1/evaluations", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/audit/events", "get")
	assertOpenAPIDescription(t, paths, "/api/v1/cache/decisions", "delete")
	assertOpenAPIDescription(t, paths, "/api/v1/cache/metadata", "delete")
	assertOpenAPIRequestBodyContentTypes(t, paths, "/api/v1/policies", "post", "application/json")
	assertOpenAPIRequestBodyContentTypes(t, paths, "/api/v1/policies/{id}", "put", "application/json")
	assertOpenAPIRequestBodyContentTypes(t, paths, "/api/v1/policies/{id}/rollback", "post", "application/json")
	assertOpenAPIRequestBodyContentTypes(t, paths, "/api/v1/policies/import", "post",
		"application/json",
		"application/x-yaml",
		"application/yaml",
		"text/yaml",
		"text/x-yaml",
	)
	assertOpenAPIParameterAbsent(t, paths, "/api/v1/policies/import", "post", "header", "Content-Type")

	resp = doJSON(t, http.MethodGet, srv.URL+controlPlaneDocsPath, nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	body := decodeBodyString(t, resp)
	assert.Contains(t, body, controlPlaneOpenAPIPath+".yaml")
}

func Test_ControlPlaneReadDeadlineExceededReturnsGatewayTimeout(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	policyRepo.listErr = context.DeadlineExceeded

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies", nil, map[string]string{"X-Tenant-ID": "tenant-1"})

	assert.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "request timed out", body["error"])
}

func assertOpenAPIDescription(t *testing.T, paths map[string]any, path, method string) {
	t.Helper()

	operation := openAPIOperation(t, paths, path, method)
	assert.NotEmptyf(t, operation["description"], "description missing for %s %s", method, path)
}

func assertOpenAPIRequestBodyContentTypes(
	t *testing.T,
	paths map[string]any,
	path, method string,
	contentTypes ...string,
) {
	t.Helper()

	operation := openAPIOperation(t, paths, path, method)

	requestBody, ok := operation["requestBody"].(map[string]any)
	require.Truef(t, ok, "requestBody missing for %s %s", method, path)

	content, ok := requestBody["content"].(map[string]any)
	require.Truef(t, ok, "requestBody content missing for %s %s", method, path)

	for _, contentType := range contentTypes {
		assert.Containsf(
			t,
			content,
			contentType,
			"requestBody content type %s missing for %s %s",
			contentType,
			method,
			path,
		)
	}
}

func assertOpenAPIParameterAbsent(t *testing.T, paths map[string]any, path, method, location, name string) {
	t.Helper()

	operation := openAPIOperation(t, paths, path, method)

	parameters, ok := operation["parameters"].([]any)
	if !ok {
		return
	}

	for _, rawParameter := range parameters {
		parameter, ok := rawParameter.(map[string]any)
		require.True(t, ok)
		assert.Falsef(t,
			parameter["in"] == location && parameter["name"] == name,
			"unexpected %s parameter %q present for %s %s",
			location,
			name,
			method,
			path,
		)
	}
}

func assertOpenAPIResponseStatus(t *testing.T, paths map[string]any, path, method string, status int) {
	t.Helper()

	responses := openAPIResponses(t, paths, path, method)
	assert.Containsf(t, responses, fmt.Sprintf("%d", status), "response %d missing for %s %s", status, method, path)
}

func assertOpenAPIResponseStatusAbsent(t *testing.T, paths map[string]any, path, method string, status int) {
	t.Helper()

	responses := openAPIResponses(t, paths, path, method)
	assert.NotContainsf(
		t,
		responses,
		fmt.Sprintf("%d", status),
		"response %d should not be registered for %s %s",
		status,
		method,
		path,
	)
}

func openAPIResponses(t *testing.T, paths map[string]any, path, method string) map[string]any {
	t.Helper()

	operation := openAPIOperation(t, paths, path, method)
	responses, ok := operation["responses"].(map[string]any)
	require.Truef(t, ok, "responses missing for %s %s", method, path)
	return responses
}

func openAPIOperation(t *testing.T, paths map[string]any, path, method string) map[string]any {
	t.Helper()

	pathItem, ok := paths[path].(map[string]any)
	require.Truef(t, ok, "path %s missing or invalid", path)

	operation, ok := pathItem[method].(map[string]any)
	require.Truef(t, ok, "operation %s %s missing or invalid", method, path)
	return operation
}

func Test_PolicyCRUD(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Create
	body := map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 9.0},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[PolicyResponse](t, resp)
	assert.Equal(t, "block-critical", created.Name)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, 1, created.SchemaVersion)

	// Get
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	got := decodeJSON[PolicyResponse](t, resp)
	assert.Equal(t, created.ID, got.ID)

	// List
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]PolicyResponse](t, resp)
	assert.Len(t, list, 1)

	// Update
	body["name"] = "block-critical-updated"
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/policies/"+created.ID, body, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	updated := decodeJSON[PolicyResponse](t, resp)
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

func Test_PolicyCreateWithUpstreamScope(t *testing.T) {
	srv, _, _, upstreamRepo, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	upstream := &domain.Upstream{
		TenantID:     "tenant-1",
		Name:         "npmjs",
		Ecosystem:    domain.EcosystemNPM,
		BaseURL:      "https://registry.npmjs.org",
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemNPM),
	}
	require.NoError(t, upstreamRepo.Create(context.Background(), upstream))

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "block-critical",
		"upstream_id":    upstream.ID,
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 9.0},
	}, headers)

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[PolicyResponse](t, resp)
	assert.Equal(t, upstream.ID, created.UpstreamID)
}

func Test_PolicyCreateRejectsUnknownUpstream(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "block-critical",
		"upstream_id":    "missing-upstream",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 9.0},
	}, headers)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "policy upstream not found", body["error"])
}

func Test_PolicyCreateRejectsIncompatibleUpstream(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	upstreamResp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", map[string]any{
		"name":         "docker-hub",
		"ecosystem":    "oci",
		"base_url":     "https://registry-1.docker.io",
		"capabilities": []string{"manifest_digest_lookup"},
	}, headers)
	require.Equal(t, http.StatusCreated, upstreamResp.StatusCode)
	upstream := decodeJSON[UpstreamResponse](t, upstreamResp)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "license-check",
		"upstream_id":    upstream.ID,
		"type":           "license",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"licenses": []string{"MIT"}},
	}, headers)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `policy type "license" only supports npm upstreams`)
}

func Test_PolicyDeleteRejectsEnabledPolicy(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"enabled":        true,
		"config":         map[string]any{"max_cvss": 9.0},
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[PolicyResponse](t, resp)

	resp = doJSON(t, http.MethodDelete, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "disable policy before deleting it", body["error"])

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func Test_PolicyDeleteConflictWhenReferenced(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	policyRepo.deleteErrWithoutForce = domain.ErrPolicyInUse

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 9.0},
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[PolicyResponse](t, resp)

	resp = doJSON(t, http.MethodDelete, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "policy has recorded evaluations or decisions", body["error"])
	assert.False(t, policyRepo.lastDeleteForce)
}

func Test_PolicyForceDeleteWhenReferenced(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	policyRepo.deleteErrWithoutForce = domain.ErrPolicyInUse

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 9.0},
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[PolicyResponse](t, resp)

	resp = doJSON(t, http.MethodDelete, srv.URL+"/api/v1/policies/"+created.ID+"?force=true", nil, headers)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
	assert.True(t, policyRepo.lastDeleteForce)

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func Test_UpstreamDeleteConflict(t *testing.T) {
	srv, _, _, upstreamRepo, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	upstreamRepo.deleteErr = domain.ErrUpstreamInUse

	resp := doJSON(t, http.MethodDelete, srv.URL+"/api/v1/upstreams/up-1", nil, headers)

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "upstream is still referenced by policies", body["error"])
}

func Test_PolicyListReturnsUpgradeErrorForDeprecatedStoredConfig(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	policyRepo.listErr = domain.ErrDeprecatedPolicyConfig

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies", nil, headers)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "tenant contains deprecated stored policies; run the policy data migration", body["error"])
}

func Test_PolicyGetReturnsUpgradeErrorForDeprecatedStoredConfig(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	policyRepo.getErr = domain.ErrDeprecatedPolicyConfig

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies/p-1", nil, headers)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "tenant contains deprecated stored policies; run the policy data migration", body["error"])
}

func Test_PolicyVersionHistoryAndRollback(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	body := map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"priority":       1,
		"enabled":        true,
		"config":         map[string]any{"max_cvss": 7.0},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[PolicyResponse](t, resp)

	body["name"] = "block-critical-stricter"
	body["priority"] = 5
	body["config"] = map[string]any{"max_cvss": 9.0}
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/policies/"+created.ID, body, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies/"+created.ID+"/versions", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	versions := decodeJSON[[]PolicyVersionResponse](t, resp)
	require.Len(t, versions, 2)
	assert.Equal(t, 2, versions[0].Version)
	assert.Equal(t, 1, versions[1].Version)
	assert.Equal(t, "block-critical-stricter", versions[0].Name)
	assert.Equal(t, "block-critical", versions[1].Name)

	resp = doJSON(
		t,
		http.MethodPost,
		srv.URL+"/api/v1/policies/"+created.ID+"/rollback",
		map[string]any{"version": 1},
		headers,
	)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	rolledBack := decodeJSON[PolicyResponse](t, resp)
	assert.Equal(t, 3, rolledBack.Version)
	assert.Equal(t, "block-critical", rolledBack.Name)
	assert.Equal(t, 1, rolledBack.Priority)
}

func Test_PolicyCreateRejectsUnsupportedSchemaVersion(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"action":         "deny",
		"schema_version": 2,
		"config":         map[string]any{"max_cvss": 9.0},
	}, headers)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], "schema_version")
}

func Test_PolicyImportRequiresItemSchemaVersion(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-import"}

	body := []byte(`
policies:
  - name: block-high-cvss
    type: cvss_threshold
    action: deny
    config:
      max_cvss: 7.5
`)
	resp := doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", body, "application/x-yaml", headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	errBody := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, errBody["error"], "schema_version is required")
}

func Test_PolicyTypesEndpoint(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/policy-types", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	types := decodeJSON[[]PolicyTypeResponse](t, resp)
	require.NotEmpty(t, types)

	var found bool
	for _, descriptor := range types {
		if descriptor.Type == "license_allowlist" {
			found = true
			assert.NotEmpty(t, descriptor.Summary)
			assert.NotEmpty(t, descriptor.Description)
			assert.NotEmpty(t, descriptor.Help)
			assert.Contains(t, descriptor.Example, "license_allowlist")
			assert.Equal(t, 2, descriptor.CurrentSchemaVersion)
			assert.Equal(t, []int{1, 2}, descriptor.SupportedSchemaVersions)
			assert.Equal(t, []string{"deny"}, descriptor.SupportedActions)
			assert.Equal(t, []string{"npm"}, descriptor.SupportedEcosystems)
			assert.Equal(t, []string{"licenses"}, descriptor.RequiredCapabilities)
		}
	}
	assert.True(t, found)

	found = false
	for _, descriptor := range types {
		if descriptor.Type == "scorecard" {
			found = true
			assert.NotEmpty(t, descriptor.Summary)
			assert.NotEmpty(t, descriptor.Description)
			assert.NotEmpty(t, descriptor.Help)
			assert.Contains(t, descriptor.Example, "scorecard")
			assert.Equal(t, 1, descriptor.CurrentSchemaVersion)
			assert.Equal(t, []int{1}, descriptor.SupportedSchemaVersions)
			assert.Equal(t, []string{"deny"}, descriptor.SupportedActions)
			assert.Equal(t, []string{"npm"}, descriptor.SupportedEcosystems)
			assert.Equal(t, []string{"scorecard_lookup"}, descriptor.RequiredCapabilities)
		}
	}
	assert.True(t, found)

	found = false
	for _, descriptor := range types {
		if descriptor.Type == "namespace_allowlist" {
			found = true
			assert.NotEmpty(t, descriptor.Summary)
			assert.NotEmpty(t, descriptor.Description)
			assert.NotEmpty(t, descriptor.Help)
			assert.Contains(t, descriptor.Example, "namespace_allowlist")
			assert.Equal(t, 1, descriptor.CurrentSchemaVersion)
			assert.Equal(t, []int{1}, descriptor.SupportedSchemaVersions)
			assert.Equal(t, []string{"deny"}, descriptor.SupportedActions)
			assert.Equal(t, []string{"npm", "oci"}, descriptor.SupportedEcosystems)
			assert.Empty(t, descriptor.RequiredCapabilities)
		}
	}
	assert.True(t, found)
}

func Test_PolicyRequestValidationAcceptsAllCatalogedTypes(t *testing.T) {
	for _, descriptor := range corepolicy.TypeCatalog() {
		req := policyRequest{
			Name:          "example",
			Type:          descriptor.Type,
			SchemaVersion: descriptor.CurrentSchemaVersion,
			Action:        descriptor.SupportedActions[0],
			Config:        json.RawMessage(`{}`),
		}

		err := validateRequest(req)
		require.NoError(t, err, "cataloged type %q should be accepted by API validation", descriptor.Type)
	}
}

func Test_PolicyValidation(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "policy-without-config",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `field "config" is required`)

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "bad-type",
		"type":           "something_else",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 7.0},
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `field "type" must be one of`)

	resp = doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies", []byte(`{
		"name":"block-critical",
		"type":"cvss_threshold",
		"schema_version":1,
		"action":"deny",
		"config":{"max_cvss":7.0},
		"extra":"nope"
	}`), "application/json", headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `unknown field "extra"`)

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":   "missing-version",
		"type":   "cvss_threshold",
		"action": "deny",
		"config": map[string]any{"max_cvss": 7.0},
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `field "schema_version" is required`)
}

func Test_ScorecardPolicyRequiresScorecardCapability(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	upstreamResp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", map[string]any{
		"name":         "npmjs",
		"ecosystem":    "npm",
		"base_url":     "https://registry.npmjs.org",
		"capabilities": []string{"publish_time", "licenses"},
	}, headers)
	require.Equal(t, http.StatusCreated, upstreamResp.StatusCode)
	upstream := decodeJSON[UpstreamResponse](t, upstreamResp)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "require-secure-source-repos",
		"upstream_id":    upstream.ID,
		"type":           "scorecard",
		"schema_version": 1,
		"action":         "deny",
		"config": map[string]any{
			"min_score": 7,
		},
	}, headers)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `requires upstream capabilities scorecard_lookup`)
}

func Test_LegacyDefaultNPMUpstreamAdvertisesNewScorecardPolicySupport(t *testing.T) {
	srv, _, _, upstreamRepo, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-legacy"}

	require.NoError(t, upstreamRepo.Create(context.Background(), &domain.Upstream{
		TenantID:  "tenant-legacy",
		Name:      "npmjs-legacy",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
		Capabilities: []domain.UpstreamCapability{
			domain.UpstreamCapabilityPublishTime,
			domain.UpstreamCapabilityLicenses,
			domain.UpstreamCapabilityVulnerabilityLookup,
		},
	}))

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams", nil, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	upstreams := decodeJSON[[]UpstreamResponse](t, resp)
	require.Len(t, upstreams, 1)
	assert.Equal(
		t,
		[]string{"publish_time", "licenses", "vulnerability_lookup", "scorecard_lookup"},
		upstreams[0].Capabilities,
	)
	assert.Contains(t, upstreams[0].SupportedPolicyTypes, string(domain.PolicyTypeScorecard))
}

func Test_ScorecardPolicyAcceptsLegacyDefaultNPMUpstream(t *testing.T) {
	srv, _, policyRepo, upstreamRepo, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-legacy"}

	legacyUpstream := &domain.Upstream{
		TenantID:  "tenant-legacy",
		Name:      "npmjs-legacy",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
		Capabilities: []domain.UpstreamCapability{
			domain.UpstreamCapabilityPublishTime,
			domain.UpstreamCapabilityLicenses,
			domain.UpstreamCapabilityVulnerabilityLookup,
		},
	}
	require.NoError(t, upstreamRepo.Create(context.Background(), legacyUpstream))

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "require-secure-source-repos",
		"upstream_id":    legacyUpstream.ID,
		"type":           "scorecard",
		"schema_version": 1,
		"action":         "deny",
		"config": map[string]any{
			"min_score": 7,
		},
	}, headers)

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	policies, err := policyRepo.ListByTenant(context.Background(), "tenant-legacy")
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, domain.PolicyTypeScorecard, policies[0].Type)
}

func Test_PolicyImportDocument(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-import"}

	yamlBody := []byte(`
tenant_id: "ignored-id"
policies:
  - name: block-high-cvss
    type: cvss_threshold
    schema_version: 1
    action: deny
    config:
      max_cvss: 7.5
  - name: require-age
    type: minimum_age
    schema_version: 1
    action: deny
    config:
      min_age_days: 30
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

	jsonBody := []byte(`{
  "tenant_id": "ignored-id",
  "policies": [
    {
      "name": "block-json",
      "type": "cvss_threshold",
      "schema_version": 1,
      "action": "deny",
      "config": {
        "max_cvss": 8.0
      }
    }
  ]
}`)
	resp = doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", jsonBody, "application/json", headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result = decodeJSON[map[string]int](t, resp)
	assert.Equal(t, 1, result["imported"])
}

func Test_PolicyImportUpsertsByName(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-import"}

	initial := []byte(`
policies:
  - name: block-critical-vulnerabilities
    type: cvss_threshold
    schema_version: 1
    action: deny
    priority: 5
    config:
      max_cvss: 7.0
`)
	resp := doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", initial, "application/x-yaml", headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	updated := []byte(`
policies:
  - name: block-critical-vulnerabilities
    type: cvss_threshold
    schema_version: 1
    action: deny
    priority: 10
    config:
      max_cvss: 9.0
`)
	resp = doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", updated, "application/x-yaml", headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON[map[string]int](t, resp)
	assert.Equal(t, 1, result["imported"])

	policies, err := policyRepo.ListByTenant(context.Background(), "tenant-import")
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, 10, policies[0].Priority)
	cfg, ok := policies[0].Config.(*domain.CVSSThresholdPolicyConfig)
	require.True(t, ok)
	require.NotNil(t, cfg.MaxCVSS)
	assert.Equal(t, 9.0, *cfg.MaxCVSS)
}

func Test_PolicyImportRejectsDuplicateNamesInDocument(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-import"}

	body := []byte(`
policies:
  - name: block-critical-vulnerabilities
    type: cvss_threshold
    schema_version: 1
    action: deny
    config:
      max_cvss: 7.0
  - name: block-critical-vulnerabilities
    type: minimum_age
    schema_version: 1
    action: deny
    config:
      min_age_days: 30
`)
	resp := doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", body, "application/x-yaml", headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	errBody := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, errBody["error"], "duplicate policy name")
	assert.NotContains(t, errBody["error"], "SQLSTATE")
}

func Test_PolicyCreateConflictIsSanitized(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	body := map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 9.0},
	}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", body, headers)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	errBody := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "policy name already exists", errBody["error"])
}

func Test_PolicyRejectsDeprecatedEnforceConfig(t *testing.T) {
	srv, _, policyRepo, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	createBody := map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 7.0, "enforce": "warn"},
		"enabled":        true,
		"priority":       10,
	}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", createBody, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	createErr := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, createErr["error"], `config key "enforce" is not supported`)

	policy := &domain.Policy{
		TenantID:      "tenant-1",
		Name:          "existing",
		Type:          domain.PolicyTypeCVSSThreshold,
		Action:        domain.PolicyActionDeny,
		SchemaVersion: 1,
		Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Enabled:       true,
	}
	require.NoError(t, policyRepo.Create(context.Background(), policy))

	updateBody := map[string]any{
		"name":           "existing",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"max_cvss": 7.0, "enforce": "warn"},
		"enabled":        true,
		"priority":       10,
	}
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/policies/"+policy.ID, updateBody, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	updateErr := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, updateErr["error"], `config key "enforce" is not supported`)

	yamlBody := []byte(`
policies:
  - name: block-high-cvss
    type: cvss_threshold
    schema_version: 1
    action: deny
    config:
      max_cvss: 7.5
      enforce: warn
`)
	resp = doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", yamlBody, "application/x-yaml", headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	importErr := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, importErr["error"], `config key "enforce" is not supported`)
}

func Test_PolicyImportRejectsUnsupportedContentType(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doRaw(t, http.MethodPost, srv.URL+"/api/v1/policies/import", []byte("policies: []"), "text/plain", headers)
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], "unsupported Content-Type")
}

func Test_UpstreamCRUD(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Create
	body := map[string]any{
		"name":         "docker-hub",
		"ecosystem":    "oci",
		"base_url":     "https://registry-1.docker.io",
		"capabilities": []string{"manifest_digest_lookup"},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON[UpstreamResponse](t, resp)
	assert.Equal(t, "docker-hub", created.Name)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, []string{"manifest_digest_lookup"}, created.Capabilities)
	assert.Contains(t, created.SupportedPolicyTypes, "block_mutable_tag")
	assert.NotContains(t, created.SupportedPolicyTypes, "license")

	// Get
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	got := decodeJSON[UpstreamResponse](t, resp)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, created.Capabilities, got.Capabilities)

	// List
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]UpstreamResponse](t, resp)
	assert.Len(t, list, 1)

	// Update
	body["name"] = "docker-hub-updated"
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/upstreams/"+created.ID, body, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	updated := decodeJSON[UpstreamResponse](t, resp)
	assert.Equal(t, "docker-hub-updated", updated.Name)
	assert.Equal(t, []string{"manifest_digest_lookup"}, updated.Capabilities)

	// Delete
	resp = doJSON(t, http.MethodDelete, srv.URL+"/api/v1/upstreams/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Not found after delete
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams/"+created.ID, nil, headers)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func Test_UpstreamAuthMetadataDoesNotExposeSecrets(t *testing.T) {
	srv, _, _, upstreamRepo, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	body := map[string]any{
		"name":      "private-ghcr",
		"ecosystem": "oci",
		"base_url":  "https://ghcr.io",
		"auth": map[string]any{
			"type":     "basic",
			"username": "robot",
			"password": "super-secret",
		},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", body, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	raw := readBody(t, resp)
	assert.NotContains(t, string(raw), "super-secret")

	created := decodeJSONBytes[UpstreamResponse](t, raw)
	assert.Equal(t, "basic", created.Auth.Type)
	assert.True(t, created.Auth.Configured)
	assert.Equal(t, "robot", created.Auth.Username)

	stored, err := upstreamRepo.GetByID(context.Background(), "tenant-1", created.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.Auth)
	assert.Equal(t, "super-secret", stored.Auth.Secret)

	updateBody := map[string]any{
		"name":      "private-ghcr-renamed",
		"ecosystem": "oci",
		"base_url":  "https://ghcr.io",
	}
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/upstreams/"+created.ID, updateBody, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	updated := decodeJSON[UpstreamResponse](t, resp)
	assert.True(t, updated.Auth.Configured)
	assert.Equal(t, "basic", updated.Auth.Type)

	stored, err = upstreamRepo.GetByID(context.Background(), "tenant-1", created.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.Auth)
	assert.Equal(t, "super-secret", stored.Auth.Secret)

	updateBody["auth"] = map[string]any{"type": "none"}
	resp = doJSON(t, http.MethodPut, srv.URL+"/api/v1/upstreams/"+created.ID, updateBody, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	stored, err = upstreamRepo.GetByID(context.Background(), "tenant-1", created.ID)
	require.NoError(t, err)
	assert.Nil(t, stored.Auth)
}

func Test_UpstreamAuthValidation(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	tests := map[string]map[string]any{
		"npm auth unsupported": {
			"name":      "npm-private",
			"ecosystem": "npm",
			"base_url":  "https://registry.npmjs.org",
			"auth": map[string]any{
				"type":     "basic",
				"username": "robot",
				"password": "secret",
			},
		},
		"basic password required": {
			"name":      "oci-private",
			"ecosystem": "oci",
			"base_url":  "https://registry.example.com",
			"auth": map[string]any{
				"type":     "basic",
				"username": "robot",
			},
		},
		"bearer token required": {
			"name":      "oci-private",
			"ecosystem": "oci",
			"base_url":  "https://registry.example.com",
			"auth": map[string]any{
				"type": "bearer_token",
			},
		},
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", body, headers)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

func Test_UpstreamAllowsMultipleRegistriesPerEcosystem(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	first := map[string]string{
		"name":      "npmjs",
		"ecosystem": "npm",
		"base_url":  "https://registry.npmjs.org",
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", first, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	second := map[string]string{
		"name":      "company-npm",
		"ecosystem": "npm",
		"base_url":  "https://registry.company.example",
	}
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", second, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]UpstreamResponse](t, resp)
	assert.Len(t, list, 2)
}

func Test_UpstreamDuplicateRegistryConflictIsSanitized(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	body := map[string]string{
		"name":      "npmjs",
		"ecosystem": "npm",
		"base_url":  "https://registry.npmjs.org",
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", map[string]string{
		"name":      "npmjs-backup",
		"ecosystem": "npm",
		"base_url":  "https://registry.npmjs.org",
	}, headers)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	errBody := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "upstream registry already exists", errBody["error"])
}

func Test_UpstreamValidation(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", map[string]string{
		"name":      "npmjs",
		"ecosystem": "maven",
		"base_url":  "https://registry.npmjs.org",
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `field "ecosystem" must be one of`)

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", map[string]string{
		"name":      "npmjs",
		"ecosystem": "npm",
		"base_url":  "not-a-url",
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `field "base_url" must be a valid URL`)

	resp = doRaw(t, http.MethodPost, srv.URL+"/api/v1/upstreams", []byte(`{
		"name":"npmjs",
		"ecosystem":"npm",
		"base_url":"https://registry.npmjs.org",
		"url":"https://registry.npmjs.org"
	}`), "application/json", headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `unknown field "url"`)

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", map[string]any{
		"name":         "docker-hub",
		"ecosystem":    "oci",
		"base_url":     "https://registry-1.docker.io",
		"capabilities": []string{"licenses"},
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body = decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `capability "licenses" is not supported for oci upstreams`)
}

func Test_UpstreamUpdateRejectsScopedPolicyConflict(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	upstreamResp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", map[string]any{
		"name":         "npmjs",
		"ecosystem":    "npm",
		"base_url":     "https://registry.npmjs.org",
		"capabilities": []string{"publish_time", "licenses", "vulnerability_lookup"},
	}, headers)
	require.Equal(t, http.StatusCreated, upstreamResp.StatusCode)
	upstream := decodeJSON[UpstreamResponse](t, upstreamResp)

	policyResp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", map[string]any{
		"name":           "license-check",
		"upstream_id":    upstream.ID,
		"type":           "license",
		"schema_version": 1,
		"action":         "deny",
		"config":         map[string]any{"licenses": []string{"MIT"}},
	}, headers)
	require.Equal(t, http.StatusCreated, policyResp.StatusCode)
	policyResp.Body.Close()

	resp := doJSON(t, http.MethodPut, srv.URL+"/api/v1/upstreams/"+upstream.ID, map[string]any{
		"name":         "npmjs",
		"ecosystem":    "npm",
		"base_url":     "https://registry.npmjs.org",
		"capabilities": []string{"publish_time", "vulnerability_lookup"},
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, body["error"], `would no longer satisfy policy "license-check"`)
}

func Test_EvaluationList(t *testing.T) {
	srv, _, _, _, decisionRepo, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Seed some decisions.
	for i := range 3 {
		_ = decisionRepo.Record(context.Background(), &domain.Decision{
			ID:         fmt.Sprintf("d-%d", i),
			TenantID:   "tenant-1",
			Outcome:    domain.DecisionAllow,
			PolicyHash: fmt.Sprintf("policy-hash-%d", i),
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
	list := decodeJSON[[]DecisionResponse](t, resp)
	assert.Len(t, list, 3)
	assert.NotEmpty(t, list[0].PolicyHash)

	// With limit and offset.
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/evaluations?limit=2&offset=1", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list = decodeJSON[[]DecisionResponse](t, resp)
	assert.Len(t, list, 2)

	_ = decisionRepo.Record(context.Background(), &domain.Decision{
		ID:       "d-lodash",
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "lodash",
			Version:   "4.17.20",
		},
		Outcome:  domain.DecisionAllow,
		Warnings: []string{"[block_cvss] artifact has CVSS score 8.1 at or above threshold 7.0"},
	})

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/evaluations?search=lodash", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list = decodeJSON[[]DecisionResponse](t, resp)
	require.Len(t, list, 1)
	assert.Equal(t, "lodash", list[0].Artifact.Name)
	assert.Equal(t, "4.17.20", list[0].Artifact.Version)
	assert.Equal(t, []string{"[block_cvss] artifact has CVSS score 8.1 at or above threshold 7.0"}, list[0].Warnings)
}

func Test_EvaluationList_InvalidPaginationFallsBackToDefaults(t *testing.T) {
	srv, _, _, _, decisionRepo, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	for i := range 3 {
		_ = decisionRepo.Record(context.Background(), &domain.Decision{
			ID:       fmt.Sprintf("d-%d", i),
			TenantID: "tenant-1",
			Outcome:  domain.DecisionAllow,
		})
	}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/evaluations?limit=bogus&offset=-5", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]DecisionResponse](t, resp)
	assert.Len(t, list, 3)
}

func Test_AuditEventList(t *testing.T) {
	srv, auditRepo := setupAuditTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	now := time.Now().UTC()

	auditRepo.events = []domain.AuditEvent{
		{
			ID:            "evt-1",
			TenantID:      "tenant-1",
			CorrelationID: "req-20260503-101500-abcd12",
			EventType:     domain.AuditEventDecisionComputed,
			Source:        "core/access",
			PolicyID:      "policy-1",
			Outcome:       domain.DecisionDeny,
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "lodash",
				Version:   "4.17.20",
			},
			Message:   "decision computed",
			Payload:   map[string]any{"reason": "blocked"},
			CreatedAt: now,
		},
		{
			ID:            "evt-2",
			TenantID:      "tenant-1",
			CorrelationID: "req-20260503-101600-ffff00",
			EventType:     domain.AuditEventRequestAllowed,
			Source:        "delivery/npm",
			Outcome:       domain.DecisionAllow,
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Namespace: "@acme",
				Name:      "widget",
				Version:   "1.2.3",
			},
			Message:   "npm request allowed",
			CreatedAt: now.Add(1 * time.Minute),
		},
		{
			ID:        "evt-other",
			TenantID:  "tenant-2",
			EventType: domain.AuditEventRequestDenied,
			CreatedAt: now,
		},
	}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/audit/events", nil, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	list := decodeJSON[[]AuditEventResponse](t, resp)
	require.Len(t, list, 2)
	assert.Equal(t, "evt-1", list[0].ID)
	assert.Equal(t, "evt-2", list[1].ID)

	resp = doJSON(
		t,
		http.MethodGet,
		srv.URL+"/api/v1/audit/events?event_type=decision_computed&outcome=deny&search=lodash",
		nil,
		headers,
	)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	list = decodeJSON[[]AuditEventResponse](t, resp)
	require.Len(t, list, 1)
	assert.Equal(t, "evt-1", list[0].ID)
	assert.Equal(t, "policy-1", list[0].PolicyID)

	resp = doJSON(
		t,
		http.MethodGet,
		srv.URL+"/api/v1/audit/events?correlation_id=req-20260503-101600-ffff00",
		nil,
		headers,
	)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	list = decodeJSON[[]AuditEventResponse](t, resp)
	require.Len(t, list, 1)
	assert.Equal(t, "evt-2", list[0].ID)
	assert.Equal(t, "@acme", list[0].Artifact.Namespace)
}

func Test_AuditEventList_InvalidTimestamp(t *testing.T) {
	srv, _ := setupAuditTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/audit/events?since=not-a-time", nil, headers)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "since must be a valid RFC3339 timestamp", body["error"])
}

func Test_ClearDecisionCache(t *testing.T) {
	srv, _, _, _, _, decisionCache := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodDelete, srv.URL+"/api/v1/cache/decisions", nil, headers)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeJSON[cacheClearResponse](t, resp)
	assert.Equal(t, "cleared", body.Status)
	assert.Equal(t, "decisions", body.Cache)
	assert.Equal(t, []string{"tenant-1"}, decisionCache.invalidatedTenants)
}

func Test_ClearDecisionCache_InternalError(t *testing.T) {
	srv, _, _, _, _, decisionCache := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	decisionCache.invalidateTenantErr = fmt.Errorf("cache down")

	resp := doJSON(t, http.MethodDelete, srv.URL+"/api/v1/cache/decisions", nil, headers)

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "failed to clear decision cache", body["error"])
}

func Test_ClearMetadataCache(t *testing.T) {
	srv, _, _, _, _, _, metadataCache := setupTestServerWithCaches(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	resp := doJSON(t, http.MethodDelete, srv.URL+"/api/v1/cache/metadata", nil, headers)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeJSON[cacheClearResponse](t, resp)
	assert.Equal(t, "cleared", body.Status)
	assert.Equal(t, "metadata", body.Cache)
	assert.Equal(t, []string{"tenant-1"}, metadataCache.invalidatedTenants)
}

func Test_ClearMetadataCache_InternalError(t *testing.T) {
	srv, _, _, _, _, _, metadataCache := setupTestServerWithCaches(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}
	metadataCache.invalidateTenantErr = fmt.Errorf("cache down")

	resp := doJSON(t, http.MethodDelete, srv.URL+"/api/v1/cache/metadata", nil, headers)

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "failed to clear metadata cache", body["error"])
}

func Test_MissingTenantIDHeader(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)

	tests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"list policies", http.MethodGet, "/api/v1/policies", nil},
		{"create policy", http.MethodPost, "/api/v1/policies", map[string]any{
			"name":           "block-critical",
			"type":           "cvss_threshold",
			"schema_version": 1,
			"action":         "deny",
			"config":         map[string]any{"max_cvss": 7.0},
		}},
		{"list upstreams", http.MethodGet, "/api/v1/upstreams", nil},
		{"create upstream", http.MethodPost, "/api/v1/upstreams", map[string]string{
			"name":      "npmjs",
			"ecosystem": "npm",
			"base_url":  "https://registry.npmjs.org",
		}},
		{"list evaluations", http.MethodGet, "/api/v1/evaluations", nil},
		{"clear decision cache", http.MethodDelete, "/api/v1/cache/decisions", nil},
		{"clear metadata cache", http.MethodDelete, "/api/v1/cache/metadata", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, tc.method, srv.URL+tc.path, tc.body, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			body := decodeJSON[map[string]string](t, resp)
			assert.Contains(t, body["error"], "X-Tenant-ID")
		})
	}
}

// --- Response DTO Tests ---

func Test_TenantResponseDTO_HasLowercaseJSONTags(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)

	// Create a tenant and verify the response uses lowercase snake_case fields
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/tenants", map[string]string{"name": "test-tenant"}, nil)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Decode as map to inspect the actual JSON keys
	var data map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data))
	resp.Body.Close()

	// Verify lowercase snake_case keys exist
	assert.Contains(t, data, "id", "response should have 'id' field (lowercase)")
	assert.Contains(t, data, "name", "response should have 'name' field (lowercase)")
	assert.Contains(t, data, "created_at", "response should have 'created_at' field (lowercase snake_case)")
	assert.Contains(t, data, "updated_at", "response should have 'updated_at' field (lowercase snake_case)")

	// Verify uppercase keys do NOT exist
	assert.NotContains(t, data, "ID", "response should not have 'ID' field (capital)")
	assert.NotContains(t, data, "CreatedAt", "response should not have 'CreatedAt' field (capital)")
	assert.NotContains(t, data, "UpdatedAt", "response should not have 'UpdatedAt' field (capital)")
}

func Test_UpstreamResponseDTO_HasLowercaseJSONTags(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Create an upstream and verify the response uses lowercase snake_case fields
	body := map[string]string{
		"name":      "npmjs",
		"ecosystem": "npm",
		"base_url":  "https://registry.npmjs.org",
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/upstreams", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Decode as map to inspect the actual JSON keys
	var data map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data))
	resp.Body.Close()

	// Verify lowercase snake_case keys exist
	assert.Contains(t, data, "id", "response should have 'id' field (lowercase)")
	assert.Contains(t, data, "name", "response should have 'name' field (lowercase)")
	assert.Contains(t, data, "ecosystem", "response should have 'ecosystem' field (lowercase)")
	assert.Contains(t, data, "base_url", "response should have 'base_url' field (lowercase snake_case)")
	assert.Contains(t, data, "capabilities", "response should have 'capabilities' field (lowercase)")
	assert.Contains(
		t,
		data,
		"supported_policy_types",
		"response should have 'supported_policy_types' field (lowercase snake_case)",
	)
	assert.Contains(t, data, "created_at", "response should have 'created_at' field (lowercase snake_case)")
	assert.Contains(t, data, "updated_at", "response should have 'updated_at' field (lowercase snake_case)")

	// Verify uppercase keys do NOT exist
	assert.NotContains(t, data, "ID", "response should not have 'ID' field (capital)")
	assert.NotContains(t, data, "BaseURL", "response should not have 'BaseURL' field (capital)")
	assert.NotContains(t, data, "Ecosystem", "response should not have 'Ecosystem' field (capital)")
	assert.NotContains(t, data, "Capabilities", "response should not have 'Capabilities' field (capital)")
	assert.NotContains(
		t,
		data,
		"SupportedPolicyTypes",
		"response should not have 'SupportedPolicyTypes' field (capital)",
	)
	assert.NotContains(t, data, "CreatedAt", "response should not have 'CreatedAt' field (capital)")
	assert.NotContains(t, data, "UpdatedAt", "response should not have 'UpdatedAt' field (capital)")
}

func Test_PolicyResponseDTO_HasLowercaseJSONTags(t *testing.T) {
	srv, _, _, _, _, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Create a policy and verify the response uses lowercase snake_case fields
	body := map[string]any{
		"name":           "block-critical",
		"type":           "cvss_threshold",
		"schema_version": 1,
		"action":         "deny",
		"priority":       1,
		"enabled":        true,
		"config":         map[string]any{"max_cvss": 9.0},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/policies", body, headers)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Decode as map to inspect the actual JSON keys
	var data map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data))
	resp.Body.Close()

	// Verify lowercase snake_case keys exist
	assert.Contains(t, data, "id", "response should have 'id' field (lowercase)")
	assert.Contains(t, data, "name", "response should have 'name' field (lowercase)")
	assert.Contains(t, data, "type", "response should have 'type' field (lowercase)")
	assert.Contains(t, data, "action", "response should have 'action' field (lowercase)")
	assert.Contains(t, data, "schema_version", "response should have 'schema_version' field (lowercase snake_case)")
	assert.Contains(t, data, "config", "response should have 'config' field (lowercase)")
	assert.Contains(t, data, "priority", "response should have 'priority' field (lowercase)")
	assert.Contains(t, data, "enabled", "response should have 'enabled' field (lowercase)")
	assert.Contains(t, data, "created_at", "response should have 'created_at' field (lowercase snake_case)")
	assert.Contains(t, data, "updated_at", "response should have 'updated_at' field (lowercase snake_case)")

	// Verify uppercase keys do NOT exist
	assert.NotContains(t, data, "ID", "response should not have 'ID' field (capital)")
	assert.NotContains(t, data, "Type", "response should not have 'Type' field (capital)")
	assert.NotContains(t, data, "Action", "response should not have 'Action' field (capital)")
	assert.NotContains(t, data, "Config", "response should not have 'Config' field (capital)")
	assert.NotContains(t, data, "Priority", "response should not have 'Priority' field (capital)")
	assert.NotContains(t, data, "Enabled", "response should not have 'Enabled' field (capital)")
	assert.NotContains(t, data, "CreatedAt", "response should not have 'CreatedAt' field (capital)")
	assert.NotContains(t, data, "UpdatedAt", "response should not have 'UpdatedAt' field (capital)")
}

func Test_ListResponsesUseLowercaseJSONTags(t *testing.T) {
	srv, _, policyRepo, upstreamRepo, decisionRepo, _ := setupTestServer(t)
	headers := map[string]string{"X-Tenant-ID": "tenant-1"}

	// Create some test data
	_ = policyRepo.Create(context.Background(), &domain.Policy{
		TenantID: "tenant-1",
		Name:     "test-policy",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
	})
	_ = upstreamRepo.Create(context.Background(), &domain.Upstream{
		TenantID:     "tenant-1",
		Name:         "test-upstream",
		Ecosystem:    domain.EcosystemNPM,
		BaseURL:      "https://example.com",
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemNPM),
	})
	_ = decisionRepo.Record(context.Background(), &domain.Decision{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "express", Version: "1.0.0"},
		Outcome:  domain.DecisionAllow,
	})

	// Test policies list response
	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/policies", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var policyList []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&policyList))
	resp.Body.Close()
	assert.NotEmpty(t, policyList)
	assert.Contains(t, policyList[0], "created_at")
	assert.NotContains(t, policyList[0], "CreatedAt")

	// Test upstreams list response
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/upstreams", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var upstreamList []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&upstreamList))
	resp.Body.Close()
	assert.NotEmpty(t, upstreamList)
	assert.Contains(t, upstreamList[0], "base_url")
	assert.Contains(t, upstreamList[0], "capabilities")
	assert.NotContains(t, upstreamList[0], "TenantID")

	// Test evaluations list response
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/v1/evaluations", nil, headers)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var decisionList []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decisionList))
	resp.Body.Close()
	assert.NotEmpty(t, decisionList)
	assert.Contains(t, decisionList[0], "evaluated_at")
	assert.NotContains(t, decisionList[0], "EvaluatedAt")
}
