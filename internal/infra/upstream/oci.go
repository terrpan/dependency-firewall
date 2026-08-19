// Package upstream provides clients for fetching content from upstream registries.
package upstream

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// ociAcceptHeaders lists the media types sent in the Accept header for manifest requests.
var ociAcceptHeaders = strings.Join([]string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}, ", ")

// OCIClient implements port.UpstreamClient for OCI-compatible registries.
type OCIClient struct {
	httpClient     *http.Client
	secretResolver authSecretResolver
	bearerTokens   *bearerTokenCache
}

// OCIClientOption customizes OCI upstream client behavior.
type OCIClientOption func(*OCIClient)

// WithAuthSecretResolver resolves encrypted upstream auth secrets at request time.
func WithAuthSecretResolver(resolver authSecretResolver) OCIClientOption {
	return func(c *OCIClient) {
		c.secretResolver = resolver
	}
}

// NewOCIClient creates a new OCIClient.
func NewOCIClient(httpClient *http.Client, options ...OCIClientOption) *OCIClient {
	c := &OCIClient{
		httpClient:   httpClient,
		bearerTokens: newBearerTokenCache(defaultBearerTokenCacheMaxEntries),
	}
	for _, option := range options {
		option(c)
	}
	return c
}

// repoPath builds the repository path from namespace and name (e.g. "library/nginx").
func repoPath(artifact domain.ArtifactIdentity) string {
	if artifact.Namespace != "" {
		return artifact.Namespace + "/" + artifact.Name
	}
	return artifact.Name
}

// FetchMetadata fetches a manifest from the upstream registry.
func (c *OCIClient) FetchMetadata(
	ctx context.Context,
	upstream domain.Upstream,
	artifact domain.ArtifactIdentity,
) (*port.UpstreamResponse, error) {
	ref := artifact.Digest
	if ref == "" {
		ref = artifact.Version
	}

	url := ociManifestURL(upstream, artifact, ref)

	return c.executeOCIGet(ctx, upstream, url)
}

// FetchContent streams content from the upstream registry.
// The digest parameter must include the full digest reference (e.g. "sha256:abc123").
// The upstream.BaseURL should include the repository path context — the handler prepends
// "/v2/{repo}" to the base URL before calling this method.
func (c *OCIClient) FetchContent(
	ctx context.Context,
	upstream domain.Upstream,
	digest string,
) (*port.UpstreamResponse, error) {
	url := fmt.Sprintf("%s/blobs/%s",
		strings.TrimRight(upstream.BaseURL, "/"),
		digest,
	)

	return c.executeOCIGet(ctx, upstream, url)
}

// ResolveReference resolves a tag to a digest via HEAD request, falling back to GET.
func (c *OCIClient) ResolveReference(
	ctx context.Context,
	upstream domain.Upstream,
	artifact domain.ArtifactIdentity,
) (string, error) {
	url := ociManifestURL(upstream, artifact, artifact.Version)

	// Try HEAD first.
	digest, err := c.resolveTagHead(ctx, upstream, url)
	if err == nil && digest != "" {
		return digest, nil
	}

	// Fall back to GET.
	return c.resolveTagGet(ctx, upstream, url)
}
