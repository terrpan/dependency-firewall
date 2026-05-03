package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	bundleinfra "github.com/danielterry/dependency-firewall/internal/infra/bundle"
)

type stubTenantRepo struct {
	tenants map[string]*domain.Tenant
}

func (s *stubTenantRepo) GetByID(_ context.Context, id string) (*domain.Tenant, error) {
	tenant, ok := s.tenants[id]
	if !ok {
		return nil, domain.ErrTenantNotFound
	}
	return tenant, nil
}

func (s *stubTenantRepo) List(context.Context) ([]domain.Tenant, error) {
	return nil, nil
}

func (s *stubTenantRepo) Create(context.Context, *domain.Tenant) error {
	return nil
}

func (s *stubTenantRepo) Update(context.Context, *domain.Tenant) error {
	return nil
}

func (s *stubTenantRepo) Delete(context.Context, string) error {
	return nil
}

func TestTenantIDFromHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		host string
		want string
	}{
		{name: "subdomain host", host: "tenant-123.firewall.example.com", want: "tenant-123"},
		{name: "localhost subdomain", host: "tenant-123.localhost:8080", want: "tenant-123"},
		{name: "plain localhost", host: "localhost:8080", want: ""},
		{name: "ip address", host: "127.0.0.1:8080", want: ""},
		{name: "empty", host: "", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tenantIDFromHost(tc.host))
		})
	}
}

func TestOCITenantFromHost(t *testing.T) {
	t.Parallel()

	repo := &stubTenantRepo{
		tenants: map[string]*domain.Tenant{
			"tenant-123":    {ID: "tenant-123", Name: "Tenant 123"},
			"header-tenant": {ID: "header-tenant", Name: "Header Tenant"},
		},
	}

	handler := OCITenantFromHost()(NewTenantResolver(repo).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := TenantFromContext(r.Context())
		require.True(t, ok)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"tenant_id": tenant.ID}))
	})))

	t.Run("resolves tenant from host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://tenant-123.localhost:8080/v2/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		assert.Equal(t, "tenant-123", body["tenant_id"])
	})

	t.Run("explicit header wins", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://tenant-123.localhost:8080/v2/", nil)
		req.Header.Set("X-Tenant-ID", "header-tenant")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		assert.Equal(t, "header-tenant", body["tenant_id"])
	})

	t.Run("plain localhost still requires explicit tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v2/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestNPMTenantFromPath(t *testing.T) {
	t.Parallel()

	handler := NPMTenantFromPath()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamID, _ := UpstreamIDFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{
			"tenant_id":   r.Header.Get("X-Tenant-ID"),
			"upstream_id": upstreamID,
			"path":        r.URL.Path,
		})
	}))

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/npm/t/tenant-123/u/up-456/%40scope%2Fpkg", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := decodeBody(t, rec)
	assert.Equal(t, "tenant-123", body["tenant_id"])
	assert.Equal(t, "up-456", body["upstream_id"])
	assert.Equal(t, "/npm/@scope/pkg", body["path"])
}

func TestOCITenantFromHost_StoresUpstreamID(t *testing.T) {
	t.Parallel()

	handler := OCITenantFromHost()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamID, _ := UpstreamIDFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{
			"tenant_id":   r.Header.Get("X-Tenant-ID"),
			"upstream_id": upstreamID,
		})
	}))

	req := httptest.NewRequest(http.MethodGet, "http://u-up-456.tenant-123.localhost:8080/v2/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := decodeBody(t, rec)
	assert.Equal(t, "tenant-123", body["tenant_id"])
	assert.Equal(t, "up-456", body["upstream_id"])
}

func TestTenantResolverSupportsBundleBackedLookup(t *testing.T) {
	t.Parallel()

	lookup := bundleinfra.NewTenantLookup(bundleTenantProvider{
		bundle: &domain.TenantBundle{
			Tenant:   domain.Tenant{ID: "tenant-123", Name: "Tenant 123"},
			TenantID: "tenant-123",
		},
	})

	handler := NewTenantResolver(lookup).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := TenantFromContext(r.Context())
		require.True(t, ok)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"tenant_name": tenant.Name}))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/npm/pkg", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := decodeBody(t, rec)
	assert.Equal(t, "Tenant 123", body["tenant_name"])
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	return body
}

type bundleTenantProvider struct {
	bundle *domain.TenantBundle
}

func (p bundleTenantProvider) GetTenantBundle(context.Context, string) (*domain.TenantBundle, error) {
	return p.bundle, nil
}
