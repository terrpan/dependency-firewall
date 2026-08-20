package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type humanAuthenticatorStub struct {
	identity domain.VerifiedIdentity
	err      error
}

func (s humanAuthenticatorStub) Authenticate(context.Context, string) (domain.VerifiedIdentity, error) {
	return s.identity, s.err
}

type humanResolverStub struct {
	principal domain.AuthenticatedPrincipal
	err       error
}

func (s humanResolverStub) Resolve(context.Context, domain.VerifiedIdentity) (domain.AuthenticatedPrincipal, error) {
	return s.principal, s.err
}

type humanAuthorizerStub struct{ scope domain.AuthorizationScope }

func (s *humanAuthorizerStub) Authorize(
	_ context.Context,
	_ domain.AuthenticatedPrincipal,
	_ domain.Permission,
	scope domain.AuthorizationScope,
) error {
	s.scope = scope
	return nil
}

func TestHumanAuthentication_RequiresBearerAndRejectsTenantMismatch(t *testing.T) {
	principal := domain.AuthenticatedPrincipal{
		Principal: domain.Principal{ID: "principal-a", Status: domain.PrincipalStatusActive},
		TenantID:  "tenant-a", TenantRole: domain.TenantRoleAdmin,
	}
	api, mux := humanAuthTestAPI(
		t,
		humanAuthenticatorStub{identity: domain.VerifiedIdentity{Subject: "user-a"}},
		humanResolverStub{principal: principal},
		&humanAuthorizerStub{},
	)
	huma.Register(api, huma.Operation{OperationID: "secured", Method: http.MethodGet, Path: "/secured"},
		func(ctx context.Context, _ *struct{}) (*struct{ Body string }, error) {
			_, ok := AuthenticatedPrincipalFromContext(ctx)
			require.True(t, ok)
			return &struct{ Body string }{Body: "ok"}, nil
		})

	missing := httptest.NewRecorder()
	mux.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/secured", nil))
	assert.Equal(t, http.StatusUnauthorized, missing.Code)

	mismatchRequest := httptest.NewRequest(http.MethodGet, "/secured", nil)
	mismatchRequest.Header.Set("Authorization", "Bearer session-token")
	mismatchRequest.Header.Set("X-Tenant-ID", "tenant-b")
	mismatch := httptest.NewRecorder()
	mux.ServeHTTP(mismatch, mismatchRequest)
	assert.Equal(t, http.StatusNotFound, mismatch.Code)

	request := httptest.NewRequest(http.MethodGet, "/secured", nil)
	request.Header.Set("Authorization", "Bearer session-token")
	request.Header.Set("X-Tenant-ID", "tenant-a")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)
}

func TestHumanAuthentication_BootstrapCarriesVerifiedIdentityWithoutLocalMapping(t *testing.T) {
	identity := domain.VerifiedIdentity{Provider: "clerk", Subject: "user-a", ExternalAccountID: "org-a"}
	api, mux := humanAuthTestAPI(
		t,
		humanAuthenticatorStub{identity: identity},
		humanResolverStub{err: domain.ErrSessionBootstrapRequired},
		&humanAuthorizerStub{},
	)
	huma.Register(api, huma.Operation{OperationID: "bootstrap", Method: http.MethodPost, Path: "/bootstrap"},
		func(ctx context.Context, _ *struct{}) (*struct{ Body string }, error) {
			got, ok := VerifiedIdentityFromContext(ctx)
			require.True(t, ok)
			assert.Equal(t, identity, got)
			return &struct{ Body string }{Body: "ok"}, nil
		})

	request := httptest.NewRequest(http.MethodPost, "/bootstrap", nil)
	request.Header.Set("Authorization", "Bearer session-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)
}

func humanAuthTestAPI(
	t *testing.T,
	authenticator HumanAuthenticator,
	resolver HumanIdentityResolver,
	authorizer HumanAuthorizer,
) (huma.API, *http.ServeMux) {
	t.Helper()
	mux := http.NewServeMux()
	config := huma.DefaultConfig("test", "test")
	config.OpenAPIPath = ""
	config.DocsPath = ""
	api := humago.New(mux, config)
	api.UseMiddleware(
		HumanAuthentication(
			api,
			authenticator,
			resolver,
			authorizer,
			nil,
			func(operationID string) (HumanOperationPolicy, bool) {
				if operationID == "bootstrap" {
					return HumanOperationPolicy{AuthenticationRequired: true, Bootstrap: true}, true
				}
				return HumanOperationPolicy{
					AuthenticationRequired: true,
					Permission:             domain.PermissionAccountRead,
				}, true
			},
		),
	)
	return api, mux
}
