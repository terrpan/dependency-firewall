package port

import (
	"context"
	"io"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Enricher fetches metadata about an artifact from external sources.
type Enricher interface {
	Enrich(ctx context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error)
}

// UpstreamClient fetches content from upstream registries.
type UpstreamClient interface {
	GetManifest(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (*UpstreamResponse, error)
	GetBlob(ctx context.Context, upstream domain.Upstream, digest string) (*UpstreamResponse, error)
	ResolveTag(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (string, error)
}

// UpstreamResponse wraps a streaming response from an upstream registry.
type UpstreamResponse struct {
	StatusCode  int
	ContentType string
	Headers     map[string]string
	Body        io.ReadCloser
}
