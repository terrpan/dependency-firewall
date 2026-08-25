package middleware

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const principalContextKey contextKey = "authenticated-principal"

// PrincipalFromContext returns the authenticated human principal in a request context.
func PrincipalFromContext(ctx context.Context) (domain.AuthenticatedPrincipal, bool) {
	principal, ok := ctx.Value(principalContextKey).(domain.AuthenticatedPrincipal)
	return principal, ok && principal.Ref.Valid()
}

// ContextWithPrincipal returns a context containing an authenticated human principal.
func ContextWithPrincipal(ctx context.Context, principal domain.AuthenticatedPrincipal) context.Context {
	return context.WithValue(ctx, principalContextKey, principal)
}
