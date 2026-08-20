package clerk

import (
	"context"
	"testing"
	"time"

	clerksdk "github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/clerktest"
	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestAuthenticator_Authenticate(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name      string
		mutate    func(map[string]any)
		wantRole  domain.TenantRole
		wantError error
	}{
		{name: "owner session", mutate: setRole("owner"), wantRole: domain.TenantRoleOwner},
		{name: "admin session", mutate: setRole("admin"), wantRole: domain.TenantRoleAdmin},
		{name: "member session", mutate: setRole("member"), wantRole: domain.TenantRoleMember},
		{
			name:      "missing active account",
			mutate:    func(claims map[string]any) { delete(claims, "o") },
			wantError: domain.ErrActiveAccountRequired,
		},
		{
			name:      "pending session",
			mutate:    func(claims map[string]any) { claims["sts"] = "pending" },
			wantError: domain.ErrAuthenticationInvalid,
		},
		{
			name:      "expired session",
			mutate:    func(claims map[string]any) { claims["exp"] = now.Add(-time.Minute).Unix() },
			wantError: domain.ErrAuthenticationInvalid,
		},
		{
			name:      "future session",
			mutate:    func(claims map[string]any) { claims["nbf"] = now.Add(time.Minute).Unix() },
			wantError: domain.ErrAuthenticationInvalid,
		},
		{
			name:      "wrong issuer",
			mutate:    func(claims map[string]any) { claims["iss"] = "https://other.clerk.accounts.dev" },
			wantError: domain.ErrAuthenticationInvalid,
		},
		{
			name:      "wrong audience",
			mutate:    func(claims map[string]any) { claims["aud"] = []string{"other-api"} },
			wantError: domain.ErrAuthenticationInvalid,
		},
		{
			name:      "wrong authorized party",
			mutate:    func(claims map[string]any) { claims["azp"] = "https://evil.example.test" },
			wantError: domain.ErrAuthenticationInvalid,
		},
		{name: "unknown role", mutate: setRole("billing"), wantError: domain.ErrUnsupportedTenantRole},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validClaims(now)
			if test.mutate != nil {
				test.mutate(claims)
			}
			token, publicKey := clerktest.GenerateJWT(t, claims, "test-key")
			authenticator := &Authenticator{
				issuer:            "https://clerk.example.accounts.dev",
				audience:          "dependency-firewall",
				authorizedParties: map[string]struct{}{"https://console.example.test": {}},
				staticJWK: &clerksdk.JSONWebKey{
					Key:       publicKey,
					KeyID:     "test-key",
					Algorithm: string(jose.RS256),
					Use:       "sig",
				},
				clock: clerktest.NewClockAt(now),
				cache: make(map[string]cachedJWK),
			}

			identity, err := authenticator.Authenticate(context.Background(), token)
			if test.wantError != nil {
				require.ErrorIs(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantRole, identity.TenantRole)
			assert.Equal(t, "user_123", identity.Subject)
			assert.Equal(t, "org_123", identity.ExternalAccountID)
			assert.Equal(t, "sess_123", identity.SessionID)
		})
	}
}

func TestAuthenticator_RejectsMalformedToken(t *testing.T) {
	authenticator := &Authenticator{clock: clerksdk.NewClock(), cache: make(map[string]cachedJWK)}
	_, err := authenticator.Authenticate(context.Background(), "not-a-jwt")
	require.ErrorIs(t, err, domain.ErrAuthenticationInvalid)
}

func validClaims(now time.Time) map[string]any {
	return map[string]any{
		"v": 2, "sts": "active", "iss": "https://clerk.example.accounts.dev",
		"aud": []string{"dependency-firewall"}, "azp": "https://console.example.test",
		"sub": "user_123", "sid": "sess_123", "iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
		"o": map[string]any{"id": "org_123", "rol": "member", "slg": "acme", "per": "", "fpm": ""},
	}
}

func setRole(role string) func(map[string]any) {
	return func(claims map[string]any) { claims["o"].(map[string]any)["rol"] = role }
}
