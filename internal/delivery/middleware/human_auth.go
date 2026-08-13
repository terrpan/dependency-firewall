package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type HumanAuthenticator interface {
	Authenticate(ctx context.Context, token string) (domain.VerifiedIdentity, error)
}

type HumanIdentityResolver interface {
	Resolve(ctx context.Context, identity domain.VerifiedIdentity) (domain.AuthenticatedPrincipal, error)
}

type HumanAuthorizer interface {
	Authorize(ctx context.Context, principal domain.AuthenticatedPrincipal, permission domain.Permission, scope domain.AuthorizationScope) error
}

type HumanMembershipVerifier interface {
	FreshTenantRole(ctx context.Context, identity domain.VerifiedIdentity) (domain.TenantRole, error)
}

type HumanOperationPolicy struct {
	AuthenticationRequired bool
	Permission             domain.Permission
	Bootstrap              bool
	FreshMembership        bool
	ScopedAuthorization    bool
}

type HumanOperationPolicyLookup func(operationID string) (HumanOperationPolicy, bool)

type humanContextKey uint8

const (
	verifiedIdentityKey humanContextKey = iota
	authenticatedPrincipalKey
)

func VerifiedIdentityFromContext(ctx context.Context) (domain.VerifiedIdentity, bool) {
	identity, ok := ctx.Value(verifiedIdentityKey).(domain.VerifiedIdentity)
	return identity, ok
}

func AuthenticatedPrincipalFromContext(ctx context.Context) (domain.AuthenticatedPrincipal, bool) {
	principal, ok := ctx.Value(authenticatedPrincipalKey).(domain.AuthenticatedPrincipal)
	return principal, ok
}

// HumanAuthentication authenticates and authorizes Clerk-mode Huma operations.
// Client-selected Tenant headers are treated only as selectors and must match
// the account resolved from the verified session.
func HumanAuthentication(
	api huma.API,
	authenticator HumanAuthenticator,
	resolver HumanIdentityResolver,
	authorizer HumanAuthorizer,
	membershipVerifier HumanMembershipVerifier,
	lookup HumanOperationPolicyLookup,
) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		policy, ok := lookup(ctx.Operation().OperationID)
		if !ok || !policy.AuthenticationRequired {
			next(ctx)
			return
		}
		token, ok := bearerToken(ctx.Header("Authorization"))
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "valid bearer authentication required")
			return
		}
		identity, err := authenticator.Authenticate(ctx.Context(), token)
		if err != nil {
			status := http.StatusUnauthorized
			message := "valid bearer authentication required"
			if errors.Is(err, domain.ErrActiveAccountRequired) {
				status = http.StatusForbidden
				message = "active account required"
			}
			_ = huma.WriteErr(api, ctx, status, message)
			return
		}
		if policy.FreshMembership {
			if membershipVerifier == nil {
				_ = huma.WriteErr(api, ctx, http.StatusServiceUnavailable, "fresh account membership verification unavailable")
				return
			}
			role, err := membershipVerifier.FreshTenantRole(ctx.Context(), identity)
			if err != nil {
				status := http.StatusServiceUnavailable
				message := "fresh account membership verification failed"
				if errors.Is(err, domain.ErrUnauthorized) || errors.Is(err, domain.ErrUnsupportedTenantRole) {
					status = http.StatusForbidden
					message = "active account membership required"
				}
				_ = huma.WriteErr(api, ctx, status, message)
				return
			}
			identity.TenantRole = role
		}
		requestContext := context.WithValue(ctx.Context(), verifiedIdentityKey, identity)
		if policy.Bootstrap {
			setHumaRequestContext(ctx, requestContext)
			next(ctx)
			return
		}
		principal, err := resolver.Resolve(requestContext, identity)
		if err != nil {
			status := http.StatusInternalServerError
			message := "failed to resolve authenticated session"
			if errors.Is(err, domain.ErrSessionBootstrapRequired) {
				status = http.StatusForbidden
				message = "session bootstrap required"
			} else if errors.Is(err, domain.ErrUnauthorized) {
				status = http.StatusForbidden
				message = "access denied"
			}
			_ = huma.WriteErr(api, ctx, status, message)
			return
		}
		if selectedTenant := strings.TrimSpace(ctx.Header("X-Tenant-ID")); selectedTenant != "" && selectedTenant != principal.TenantID {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "resource not found")
			return
		}
		if policy.Permission != "" && !policy.ScopedAuthorization {
			err = authorizer.Authorize(requestContext, principal, policy.Permission, domain.AuthorizationScope{TenantID: principal.TenantID})
			if err != nil {
				status := http.StatusInternalServerError
				message := "authorization failed"
				var denial *domain.AuthorizationError
				if errors.As(err, &denial) {
					status = http.StatusForbidden
					message = "insufficient permission"
				}
				_ = huma.WriteErr(api, ctx, status, message)
				return
			}
		}
		requestContext = context.WithValue(requestContext, authenticatedPrincipalKey, principal)
		setHumaRequestContext(ctx, requestContext)
		next(ctx)
	}
}

func setHumaRequestContext(ctx huma.Context, requestContext context.Context) {
	request, _ := humago.Unwrap(ctx)
	*request = *request.WithContext(requestContext)
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	returnToken := ""
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		returnToken = strings.TrimSpace(parts[1])
	}
	return returnToken, returnToken != ""
}
