package proxyflow

import (
	"context"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

func RequestIDFromContext(ctx context.Context) string {
	requestID, _ := middleware.RequestIDFromContext(ctx)
	return requestID
}

func NewAccessRequest(ctx context.Context, tenantID string, upstream domain.Upstream, artifact domain.ArtifactIdentity) domain.AccessRequest {
	return domain.AccessRequest{
		TenantID:  tenantID,
		RequestID: RequestIDFromContext(ctx),
		Artifact:  artifact,
		Upstream:  upstream,
		Timestamp: time.Now(),
	}
}

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
