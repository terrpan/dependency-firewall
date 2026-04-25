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
