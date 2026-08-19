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
	return domain.AccessRequest{
		TenantID:  tenantID,
		RequestID: RequestIDFromContext(ctx),
		Artifact:  artifact,
		Upstream:  upstream,
		Timestamp: time.Now(),
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
