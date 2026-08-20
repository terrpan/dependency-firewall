package proxyflow

import (
	"context"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

// RequestIDFromContext returns the request ID assigned by middleware, or the empty string when the context carries
// none. The value becomes the audit correlation ID that ties every event of one proxy request together.
func RequestIDFromContext(ctx context.Context) string {
	requestID, _ := middleware.RequestIDFromContext(ctx)
	return requestID
}

// NewAccessRequest builds the protocol-neutral evaluation input that a protocol adapter hands to the policy engine,
// stamping it with the correlating request ID and the current time. Kind, enrichment metadata and dependency context
// are left unset for the caller and the engine to populate.
func NewAccessRequest(
	ctx context.Context,
	tenantID string,
	upstream domain.Upstream,
	artifact domain.ArtifactIdentity,
) domain.AccessRequest {
	scope := AccessScope(ctx, tenantID)
	credentialID := ""
	if credential, ok := middleware.CredentialFromContext(ctx); ok {
		credentialID = credential.ID
	}
	return domain.AccessRequest{
		TenantID:       scope.TenantID,
		OrganizationID: scope.OrganizationID,
		TeamID:         scope.TeamID,
		CredentialID:   credentialID,
		RequestID:      RequestIDFromContext(ctx),
		Artifact:       artifact,
		Upstream:       upstream,
		Timestamp:      time.Now(),
	}
}

// AccessScope derives the operational scope exclusively from an authenticated
// data-plane credential. Client-supplied Organization and Team selectors are
// deliberately not part of this API.
func AccessScope(ctx context.Context, tenantID string) domain.AuthorizationScope {
	credential, ok := middleware.CredentialFromContext(ctx)
	if !ok {
		return domain.AuthorizationScope{TenantID: tenantID}
	}
	// The middleware only places a verifier in context after comparing its
	// Tenant ID with the routed Tenant. Keep this check here as a second
	// boundary so a forged context cannot widen a request's scope.
	if credential.TenantID != "" && credential.TenantID != tenantID {
		return domain.AuthorizationScope{TenantID: tenantID}
	}
	return domain.AuthorizationScope{
		TenantID:       tenantID,
		OrganizationID: credential.OrganizationID,
		TeamID:         credential.TeamID,
	}
}

// ResolveUpstream determines which upstream registry a proxy request targets. When routing middleware pinned a
// specific upstream, that one is used and rejected with domain.ErrUpstreamNotFound if it belongs to a different
// ecosystem; otherwise the tenant's upstream for the requested ecosystem is used. Lookups are tenant-scoped.
func ResolveUpstream(
	ctx context.Context,
	upstreams port.UpstreamRepository,
	tenantID string,
	ecosystem domain.EcosystemType,
) (*domain.Upstream, error) {
	scope := AccessScope(ctx, tenantID)
	if scoped, ok := upstreams.(port.ScopedUpstreamRepository); ok {
		if upstreamID, found := middleware.UpstreamIDFromContext(ctx); found && upstreamID != "" {
			upstream, err := scoped.GetVisibleByID(ctx, scope, upstreamID)
			if err != nil {
				return nil, err
			}
			if upstream.Ecosystem != ecosystem {
				return nil, domain.ErrUpstreamNotFound
			}
			return upstream, nil
		}
		return scoped.ResolveVisibleByEcosystem(ctx, scope, ecosystem)
	}
	if scope.OrganizationID != "" || scope.TeamID != "" {
		return nil, domain.ErrUpstreamNotFound
	}
	if upstreamID, ok := middleware.UpstreamIDFromContext(ctx); ok && upstreamID != "" {
		upstream, err := upstreams.GetByID(ctx, tenantID, upstreamID)
		if err != nil {
			return nil, err
		}
		if upstream.Ecosystem != ecosystem {
			return nil, domain.ErrUpstreamNotFound
		}
		return upstream, nil
	}

	return upstreams.GetByEcosystem(ctx, tenantID, ecosystem)
}
