package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type identityLinkGetterStub struct{ link *domain.TenantIdentityLink }

func (s identityLinkGetterStub) GetByExternalID(context.Context, string, string) (*domain.TenantIdentityLink, error) {
	if s.link == nil {
		return nil, domain.ErrTenantIdentityLinkNotFound
	}
	return s.link, nil
}

type identityPrincipalGetterStub struct{ principal *domain.Principal }

func (s identityPrincipalGetterStub) GetByIdentity(context.Context, string, string) (*domain.Principal, error) {
	if s.principal == nil {
		return nil, domain.ErrPrincipalNotFound
	}
	return s.principal, nil
}

func TestIdentityService_Resolve(t *testing.T) {
	resolver := NewIdentityService(
		identityLinkGetterStub{link: &domain.TenantIdentityLink{TenantID: "tenant-a"}},
		identityPrincipalGetterStub{
			principal: &domain.Principal{ID: "principal-a", Status: domain.PrincipalStatusActive},
		},
	)

	principal, err := resolver.Resolve(context.Background(), domain.VerifiedIdentity{
		Provider: "clerk", Subject: "user-a", ExternalAccountID: "org-a", TenantRole: domain.TenantRoleAdmin,
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", principal.TenantID)
	assert.Equal(t, "principal-a", principal.Principal.ID)
	assert.Equal(t, domain.TenantRoleAdmin, principal.TenantRole)
}

func TestIdentityService_RequiresBootstrapForUnknownMapping(t *testing.T) {
	resolver := NewIdentityService(identityLinkGetterStub{}, identityPrincipalGetterStub{})
	_, err := resolver.Resolve(context.Background(), domain.VerifiedIdentity{
		Provider: "clerk", Subject: "user-a", ExternalAccountID: "org-a",
	})
	require.ErrorIs(t, err, domain.ErrSessionBootstrapRequired)
}

type bootstrapDirectoryStub struct {
	request domain.SessionBootstrapRequest
	role    domain.TenantRole
}

func (s bootstrapDirectoryStub) BootstrapRequest(
	context.Context,
	domain.VerifiedIdentity,
) (domain.SessionBootstrapRequest, domain.TenantRole, error) {
	return s.request, s.role, nil
}

type bootstrapStoreStub struct{ calls int }

func (s *bootstrapStoreStub) Bootstrap(
	_ context.Context,
	request domain.SessionBootstrapRequest,
) (*domain.SessionBootstrapResult, error) {
	s.calls++
	return &domain.SessionBootstrapResult{
		Tenant:    domain.Tenant{ID: "tenant-a"},
		Principal: domain.Principal{ID: "principal-a"},
	}, nil
}

func TestSessionBootstrapServiceRejectsProviderScopeSubstitution(t *testing.T) {
	store := &bootstrapStoreStub{}
	service := NewSessionBootstrapService(bootstrapDirectoryStub{request: domain.SessionBootstrapRequest{
		Provider: "clerk", ExternalAccountID: "org-other", ExternalSubject: "user-a",
	}}, store)

	_, _, err := service.Bootstrap(context.Background(), domain.VerifiedIdentity{
		Provider: "clerk", ExternalAccountID: "org-a", Subject: "user-a",
	})
	require.ErrorIs(t, err, domain.ErrAuthenticationInvalid)
	assert.Zero(t, store.calls)
}
