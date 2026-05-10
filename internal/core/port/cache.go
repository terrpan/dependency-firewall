package port

import (
	"context"
	"io"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DecisionCache caches evaluated decisions.
type DecisionCache interface {
	Get(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error)
	Set(ctx context.Context, decision *domain.Decision, ttl time.Duration) error
	Invalidate(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) error
	InvalidateTenant(ctx context.Context, tenantID string) error
}

// MetadataCache caches enrichment metadata.
type MetadataCache interface {
	Get(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error)
	Set(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity, metadata *domain.ArtifactMetadata, ttl time.Duration) error
	InvalidateTenant(ctx context.Context, tenantID string) error
}

// OCIArtifactKind identifies the OCI artifact type stored in the cache.
type OCIArtifactKind string

const (
	OCIArtifactManifest OCIArtifactKind = "manifests"
	OCIArtifactBlob     OCIArtifactKind = "blobs"
)

// OCIArtifactDescriptor stores cacheable response metadata for an OCI artifact.
type OCIArtifactDescriptor struct {
	ContentType string
	Headers     map[string]string
}

// OCIArtifactWriter stages a cache write for an OCI artifact.
type OCIArtifactWriter interface {
	io.Writer
	Commit(ctx context.Context) error
	Abort() error
}

// OCIArtifactCache caches OCI manifests and blobs by tenant, upstream, and immutable digest.
type OCIArtifactCache interface {
	Get(ctx context.Context, tenantID string, upstreamID string, kind OCIArtifactKind, digest string) (*UpstreamResponse, error)
	StartWrite(ctx context.Context, tenantID string, upstreamID string, kind OCIArtifactKind, digest string, descriptor OCIArtifactDescriptor) (OCIArtifactWriter, error)
}
