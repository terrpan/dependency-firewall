package proxyflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

type credentialBundleStub struct{ bundle *domain.TenantBundle }

func (b credentialBundleStub) GetTenantBundle(context.Context, string) (*domain.TenantBundle, error) {
	return b.bundle, nil
}

type scopedUpstreamRepoStub struct {
	upstreamRepoStub
	visibleByEcosystem *domain.Upstream
	lastScope          domain.AuthorizationScope
}

func (s *scopedUpstreamRepoStub) GetVisibleByID(
	_ context.Context,
	scope domain.AuthorizationScope,
	id string,
) (*domain.Upstream, error) {
	s.lastScope = scope
	if s.byID == nil || s.byID.ID != id {
		return nil, domain.ErrUpstreamNotFound
	}
	return s.byID, nil
}

func (s *scopedUpstreamRepoStub) ListVisible(
	_ context.Context,
	scope domain.AuthorizationScope,
) ([]domain.Upstream, error) {
	s.lastScope = scope
	if s.visibleByEcosystem == nil {
		return []domain.Upstream{}, nil
	}
	return []domain.Upstream{*s.visibleByEcosystem}, nil
}

func (s *scopedUpstreamRepoStub) ResolveVisibleByEcosystem(
	_ context.Context,
	scope domain.AuthorizationScope,
	ecosystem domain.EcosystemType,
) (*domain.Upstream, error) {
	s.lastScope = scope
	if s.visibleByEcosystem == nil || s.visibleByEcosystem.Ecosystem != ecosystem {
		return nil, domain.ErrUpstreamNotFound
	}
	return s.visibleByEcosystem, nil
}

type upstreamRepoStub struct {
	byID               *domain.Upstream
	byEcosystem        *domain.Upstream
	errByID            error
	errByEcosystem     error
	lastByIDTenant     string
	lastByIDUpstreamID string
	lastByEcoTenant    string
	lastByEco          domain.EcosystemType
}

func (s *upstreamRepoStub) GetByID(_ context.Context, tenantID, id string) (*domain.Upstream, error) {
	s.lastByIDTenant = tenantID
	s.lastByIDUpstreamID = id
	if s.errByID != nil {
		return nil, s.errByID
	}
	return s.byID, nil
}

func (s *upstreamRepoStub) GetByEcosystem(
	_ context.Context,
	tenantID string,
	eco domain.EcosystemType,
) (*domain.Upstream, error) {
	s.lastByEcoTenant = tenantID
	s.lastByEco = eco
	if s.errByEcosystem != nil {
		return nil, s.errByEcosystem
	}
	return s.byEcosystem, nil
}

func (*upstreamRepoStub) ListByTenant(context.Context, string) ([]domain.Upstream, error) {
	return nil, nil
}

func (*upstreamRepoStub) Create(context.Context, *domain.Upstream) error {
	return nil
}

func (*upstreamRepoStub) Update(context.Context, *domain.Upstream) error {
	return nil
}

func (*upstreamRepoStub) Delete(context.Context, string, string) error {
	return nil
}

func TestResolveUpstream_UsesEcosystemWhenNoContextUpstream(t *testing.T) {
	t.Parallel()

	repo := &upstreamRepoStub{
		byEcosystem: &domain.Upstream{ID: "up-npm", Ecosystem: domain.EcosystemNPM},
	}

	upstream, err := ResolveUpstream(context.Background(), repo, "tenant-1", domain.EcosystemNPM)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if upstream == nil || upstream.ID != "up-npm" {
		t.Fatalf("unexpected upstream: %#v", upstream)
	}
	if repo.lastByEcoTenant != "tenant-1" || repo.lastByEco != domain.EcosystemNPM {
		t.Fatalf("expected ecosystem lookup, got tenant=%q eco=%q", repo.lastByEcoTenant, repo.lastByEco)
	}
}

func TestResolveUpstream_UsesContextUpstreamID(t *testing.T) {
	t.Parallel()

	repo := &upstreamRepoStub{
		byID: &domain.Upstream{ID: "up-123", Ecosystem: domain.EcosystemNPM},
	}
	ctx := middleware.ContextWithUpstreamID(context.Background(), "up-123")

	upstream, err := ResolveUpstream(ctx, repo, "tenant-1", domain.EcosystemNPM)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if upstream == nil || upstream.ID != "up-123" {
		t.Fatalf("unexpected upstream: %#v", upstream)
	}
	if repo.lastByIDTenant != "tenant-1" || repo.lastByIDUpstreamID != "up-123" {
		t.Fatalf("expected id lookup, got tenant=%q id=%q", repo.lastByIDTenant, repo.lastByIDUpstreamID)
	}
}

func TestResolveUpstream_ErrorsWhenContextUpstreamWrongEcosystem(t *testing.T) {
	t.Parallel()

	repo := &upstreamRepoStub{
		byID: &domain.Upstream{ID: "up-123", Ecosystem: domain.EcosystemOCI},
	}
	ctx := middleware.ContextWithUpstreamID(context.Background(), "up-123")

	upstream, err := ResolveUpstream(ctx, repo, "tenant-1", domain.EcosystemNPM)
	if err == nil {
		t.Fatalf("expected error, got nil (upstream=%#v)", upstream)
	}
	if err != domain.ErrUpstreamNotFound {
		t.Fatalf("expected ErrUpstreamNotFound, got %v", err)
	}
}

func TestNewAccessRequest_UsesContextRequestID(t *testing.T) {
	t.Parallel()

	artifact := domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "left-pad", Version: "1.3.0"}
	upstream := domain.Upstream{ID: "up-1", Ecosystem: domain.EcosystemNPM}

	var built domain.AccessRequest
	h := middleware.RequestID()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		built = NewAccessRequest(r.Context(), "tenant-1", upstream, artifact)
	}))

	req := httptest.NewRequest(http.MethodGet, "/npm/left-pad", nil)
	rec := httptest.NewRecorder()
	before := time.Now().Add(-time.Second)
	h.ServeHTTP(rec, req)

	if built.TenantID != "tenant-1" {
		t.Fatalf("unexpected tenant id: %q", built.TenantID)
	}
	if built.Upstream.ID != "up-1" {
		t.Fatalf("unexpected upstream id: %q", built.Upstream.ID)
	}
	if built.Artifact.Name != "left-pad" || built.Artifact.Version != "1.3.0" {
		t.Fatalf("unexpected artifact: %#v", built.Artifact)
	}
	if built.RequestID == "" {
		t.Fatal("expected request id from middleware, got empty")
	}
	if built.Timestamp.Before(before) {
		t.Fatalf("unexpected timestamp: %s", built.Timestamp)
	}
}

func TestCredentialScopeControlsUpstreamAndAccessRequest(t *testing.T) {
	t.Parallel()

	secret := "scope-bound-secret"
	digest := sha256.Sum256([]byte(secret))
	credential := domain.DataPlaneCredentialVerifier{
		ID:             "credential-1",
		TenantID:       "tenant-1",
		OrganizationID: "organization-1",
		TeamID:         "team-1",
		SecretDigest:   hex.EncodeToString(digest[:]),
	}
	repo := &scopedUpstreamRepoStub{
		visibleByEcosystem: &domain.Upstream{ID: "team-upstream", Ecosystem: domain.EcosystemNPM},
	}
	var accessRequest domain.AccessRequest
	middlewareHandler := middleware.NewDataPlaneCredentialMiddleware(credentialBundleStub{
		bundle: &domain.TenantBundle{Credentials: []domain.DataPlaneCredentialVerifier{credential}},
	}).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		upstream, err := ResolveUpstream(r.Context(), repo, "tenant-1", domain.EcosystemNPM)
		if err != nil {
			t.Errorf("ResolveUpstream() error = %v", err)
			return
		}
		accessRequest = NewAccessRequest(
			r.Context(),
			"tenant-1",
			*upstream,
			domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "pkg", Version: "1.0.0"},
		)
	}))

	req := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("Authorization", "Bearer "+secret)
	middlewareHandler.ServeHTTP(httptest.NewRecorder(), req)

	if repo.lastScope != (domain.AuthorizationScope{TenantID: "tenant-1", OrganizationID: "organization-1", TeamID: "team-1"}) {
		t.Fatalf("upstream resolved with wrong scope: %#v", repo.lastScope)
	}
	if accessRequest.OrganizationID != "organization-1" || accessRequest.TeamID != "team-1" ||
		accessRequest.CredentialID != "credential-1" {
		t.Fatalf("access request did not retain credential scope: %#v", accessRequest)
	}
}
