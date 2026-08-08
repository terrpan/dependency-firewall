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

// UpstreamClient fetches metadata and content from upstream registries.
type UpstreamClient interface {
	FetchMetadata(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (*UpstreamResponse, error)
	FetchContent(ctx context.Context, upstream domain.Upstream, locator string) (*UpstreamResponse, error)
	ResolveReference(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (string, error)
}

// NPMManifestDependencyLister lists the dependency package names declared by
// one concrete npm package version manifest.
type NPMManifestDependencyLister interface {
	ListManifestDependencyNames(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) ([]string, error)
}

// UpstreamResponse wraps a streaming response from an upstream registry.
type UpstreamResponse struct {
	StatusCode  int
	ContentType string
	Headers     map[string]string
	Body        io.ReadCloser
}
