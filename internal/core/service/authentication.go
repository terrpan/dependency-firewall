package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type identityTenantLinkGetter interface {
	GetByExternalID(ctx context.Context, provider, externalID string) (*domain.TenantIdentityLink, error)
}

type identityPrincipalGetter interface {
	GetByIdentity(ctx context.Context, provider, externalSubject string) (*domain.Principal, error)
}

// IdentityService resolves a verified provider identity to the local account
// and Principal projection. It does not verify external tokens.
type IdentityService struct {
	links      identityTenantLinkGetter
	principals identityPrincipalGetter
}

func NewIdentityService(links identityTenantLinkGetter, principals identityPrincipalGetter) *IdentityService {
	return &IdentityService{links: links, principals: principals}
}

func (s *IdentityService) Resolve(ctx context.Context, identity domain.VerifiedIdentity) (domain.AuthenticatedPrincipal, error) {
	if strings.TrimSpace(identity.Provider) == "" || strings.TrimSpace(identity.Subject) == "" ||
		strings.TrimSpace(identity.ExternalAccountID) == "" {
		return domain.AuthenticatedPrincipal{}, domain.ErrAuthenticationInvalid
	}
	link, err := s.links.GetByExternalID(ctx, identity.Provider, identity.ExternalAccountID)
	if errors.Is(err, domain.ErrTenantIdentityLinkNotFound) {
		return domain.AuthenticatedPrincipal{}, domain.ErrSessionBootstrapRequired
	}
	if err != nil {
		return domain.AuthenticatedPrincipal{}, fmt.Errorf("resolving account identity: %w", err)
	}
	principal, err := s.principals.GetByIdentity(ctx, identity.Provider, identity.Subject)
	if errors.Is(err, domain.ErrPrincipalNotFound) {
		return domain.AuthenticatedPrincipal{}, domain.ErrSessionBootstrapRequired
	}
	if err != nil {
		return domain.AuthenticatedPrincipal{}, fmt.Errorf("resolving principal identity: %w", err)
	}
	if principal.Status != domain.PrincipalStatusActive {
		return domain.AuthenticatedPrincipal{}, domain.ErrUnauthorized
	}
	return domain.AuthenticatedPrincipal{
		Principal: *principal, TenantID: link.TenantID, TenantRole: identity.TenantRole,
		Provider: identity.Provider, ExternalAccountID: identity.ExternalAccountID,
	}, nil
}

type SessionBootstrapDirectory interface {
	BootstrapRequest(ctx context.Context, identity domain.VerifiedIdentity) (domain.SessionBootstrapRequest, domain.TenantRole, error)
}

type sessionBootstrapStore interface {
	Bootstrap(ctx context.Context, request domain.SessionBootstrapRequest) (*domain.SessionBootstrapResult, error)
}

// SessionBootstrapService performs fresh provider reconciliation before opening
// the local atomic provisioning transaction.
type SessionBootstrapService struct {
	directory SessionBootstrapDirectory
	store     sessionBootstrapStore
}

func NewSessionBootstrapService(directory SessionBootstrapDirectory, store sessionBootstrapStore) *SessionBootstrapService {
	return &SessionBootstrapService{directory: directory, store: store}
}

func (s *SessionBootstrapService) Bootstrap(ctx context.Context, identity domain.VerifiedIdentity) (*domain.SessionBootstrapResult, domain.TenantRole, error) {
	request, role, err := s.directory.BootstrapRequest(ctx, identity)
	if err != nil {
		return nil, "", err
	}
	if request.Provider != identity.Provider || request.ExternalAccountID != identity.ExternalAccountID ||
		request.ExternalSubject != identity.Subject {
		return nil, "", domain.ErrAuthenticationInvalid
	}
	result, err := s.store.Bootstrap(ctx, request)
	if err != nil {
		return nil, "", err
	}
	return result, role, nil
}
