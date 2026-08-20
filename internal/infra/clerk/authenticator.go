package clerk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	clerksdk "github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwks"
	clerkjwt "github.com/clerk/clerk-sdk-go/v2/jwt"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Provider and its sibling constants enumerate the supported values.
const Provider = "clerk"

type cachedJWK struct {
	key       *clerksdk.JSONWebKey
	expiresAt time.Time
}

// Authenticator verifies Clerk session tokens and maps external roles into
// canonical core Tenant roles. It never performs local authorization.
type Authenticator struct {
	issuer            string
	audience          string
	authorizedParties map[string]struct{}
	leeway            time.Duration
	staticJWK         *clerksdk.JSONWebKey
	jwksClient        *jwks.Client
	clock             clerksdk.Clock

	mu    sync.RWMutex
	cache map[string]cachedJWK
}

type sessionStatusClaims struct {
	SessionStatus string `json:"sts"`
	Version       int    `json:"v"`
	Organization  struct {
		ID string `json:"id"`
	} `json:"o"`
}

// NewAuthenticator constructs a new Authenticator.
func NewAuthenticator(cfg config.AuthClerkConfig) (*Authenticator, error) {
	parties := make(map[string]struct{}, len(cfg.AuthorizedParties))
	for _, party := range cfg.AuthorizedParties {
		party = strings.TrimSpace(party)
		if party == "" {
			return nil, fmt.Errorf("creating Clerk authenticator: authorized party is blank")
		}
		parties[party] = struct{}{}
	}

	authenticator := &Authenticator{
		issuer:            strings.TrimSpace(cfg.Issuer),
		audience:          strings.TrimSpace(cfg.Audience),
		authorizedParties: parties,
		leeway:            cfg.Leeway,
		clock:             clerksdk.NewClock(),
		cache:             make(map[string]cachedJWK),
	}
	if key := strings.TrimSpace(cfg.JWTKey); key != "" {
		if !strings.HasPrefix(key, "-----BEGIN") {
			key = "-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"
		}
		jwk, err := clerksdk.JSONWebKeyFromPEM(key)
		if err != nil {
			return nil, fmt.Errorf("creating Clerk authenticator: parsing JWT verification key: %w", err)
		}
		authenticator.staticJWK = jwk
	} else {
		clientConfig := &clerksdk.ClientConfig{}
		clientConfig.Key = clerksdk.String(strings.TrimSpace(cfg.SecretKey))
		authenticator.jwksClient = jwks.NewClient(clientConfig)
	}
	return authenticator, nil
}

// Authenticate verifies and maps a Clerk JWT to a domain identity.
func (a *Authenticator) Authenticate( //nolint:gocyclo // JWT verification and mapping steps
	ctx context.Context,
	token string,
) (domain.VerifiedIdentity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return domain.VerifiedIdentity{}, domain.ErrAuthenticationInvalid
	}
	decoded, err := clerkjwt.Decode(ctx, &clerkjwt.DecodeParams{Token: token})
	if err != nil || decoded.KeyID == "" {
		return domain.VerifiedIdentity{}, domain.ErrAuthenticationInvalid
	}

	jwk, err := a.getJWK(ctx, decoded.KeyID, false)
	if err != nil {
		return domain.VerifiedIdentity{}, fmt.Errorf("verifying Clerk session: loading JWK: %w", err)
	}
	claims, privateClaims, err := a.verify(ctx, token, jwk)
	if err != nil && a.staticJWK == nil {
		// A signing-key rotation can invalidate a still-cached key. Refresh once;
		// ordinary invalid tokens still fail closed after the bounded retry.
		jwk, refreshErr := a.getJWK(ctx, decoded.KeyID, true)
		if refreshErr == nil {
			claims, privateClaims, err = a.verify(ctx, token, jwk)
		}
	}
	if err != nil {
		return domain.VerifiedIdentity{}, domain.ErrAuthenticationInvalid
	}
	if privateClaims.Version != 2 || privateClaims.SessionStatus != "active" {
		return domain.VerifiedIdentity{}, domain.ErrAuthenticationInvalid
	}
	if privateClaims.Organization.ID == "" {
		return domain.VerifiedIdentity{}, domain.ErrActiveAccountRequired
	}
	if claims.Issuer != a.issuer || !contains(claims.Audience, a.audience) {
		return domain.VerifiedIdentity{}, domain.ErrAuthenticationInvalid
	}
	if _, ok := a.authorizedParties[claims.AuthorizedParty]; !ok {
		return domain.VerifiedIdentity{}, domain.ErrAuthenticationInvalid
	}
	if claims.Subject == "" || claims.SessionID == "" {
		return domain.VerifiedIdentity{}, domain.ErrAuthenticationInvalid
	}
	if claims.ActiveOrganizationID == "" {
		return domain.VerifiedIdentity{}, domain.ErrActiveAccountRequired
	}

	role, err := tenantRole(claims.ActiveOrganizationRole)
	if err != nil {
		return domain.VerifiedIdentity{}, err
	}
	return domain.VerifiedIdentity{
		Provider: Provider, Subject: claims.Subject,
		ExternalAccountID: claims.ActiveOrganizationID,
		TenantRole:        role, SessionID: claims.SessionID,
	}, nil
}

func (a *Authenticator) verify(
	ctx context.Context,
	token string,
	jwk *clerksdk.JSONWebKey,
) (*clerksdk.SessionClaims, *sessionStatusClaims, error) {
	claims, err := clerkjwt.Verify(ctx, &clerkjwt.VerifyParams{
		Token:  token,
		JWK:    jwk,
		Clock:  a.clock,
		Leeway: a.leeway,
		AuthorizedPartyHandler: func(party string) bool {
			_, ok := a.authorizedParties[party]
			return ok
		},
		CustomClaimsConstructor: func(context.Context) any { return &sessionStatusClaims{} },
	})
	if err != nil {
		return nil, nil, err
	}
	custom, ok := claims.Custom.(*sessionStatusClaims)
	if !ok {
		return nil, nil, errors.New("missing Clerk session status claims")
	}
	return claims, custom, nil
}

func (a *Authenticator) getJWK(ctx context.Context, keyID string, refresh bool) (*clerksdk.JSONWebKey, error) {
	if a.staticJWK != nil {
		return a.staticJWK, nil
	}
	now := a.clock.Now().UTC()
	if !refresh {
		a.mu.RLock()
		entry, ok := a.cache[keyID]
		a.mu.RUnlock()
		if ok && entry.key != nil && entry.expiresAt.After(now) {
			return entry.key, nil
		}
	}
	jwk, err := clerkjwt.GetJSONWebKey(ctx, &clerkjwt.GetJSONWebKeyParams{
		KeyID: keyID, JWKSClient: a.jwksClient,
	})
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.cache[keyID] = cachedJWK{key: jwk, expiresAt: now.Add(time.Hour)}
	a.mu.Unlock()
	return jwk, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func tenantRole(role string) (domain.TenantRole, error) {
	switch strings.TrimSpace(role) {
	case "org:owner":
		return domain.TenantRoleOwner, nil
	case "org:admin":
		return domain.TenantRoleAdmin, nil
	case "org:member":
		return domain.TenantRoleMember, nil
	default:
		return "", domain.ErrUnsupportedTenantRole
	}
}
