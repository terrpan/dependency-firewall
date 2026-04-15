// Package upstream provides clients for fetching content from upstream registries.
package upstream

import (
	"context"
	"fmt"
	"io"
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
	httpClient *http.Client
}

// NewOCIClient creates a new OCIClient.
func NewOCIClient(httpClient *http.Client) *OCIClient {
	return &OCIClient{httpClient: httpClient}
}

// repoPath builds the repository path from namespace and name (e.g. "library/nginx").
func repoPath(artifact domain.ArtifactIdentity) string {
	if artifact.Namespace != "" {
		return artifact.Namespace + "/" + artifact.Name
	}
	return artifact.Name
}

// GetManifest fetches a manifest from the upstream registry.
func (c *OCIClient) GetManifest(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	ref := artifact.Version
	if ref == "" {
		ref = artifact.Digest
	}

	url := fmt.Sprintf("%s/v2/%s/manifests/%s",
		strings.TrimRight(upstream.BaseURL, "/"),
		repoPath(artifact),
		ref,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating manifest request: %w", err)
	}
	req.Header.Set("Accept", ociAcceptHeaders)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUpstreamUnavailable, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, domain.ErrArtifactNotFound
	}

	headers := extractHeaders(resp)

	return &port.UpstreamResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Headers:     headers,
		Body:        resp.Body,
	}, nil
}

// GetBlob streams a blob from the upstream registry.
// The digest parameter must include the full digest reference (e.g. "sha256:abc123").
// The upstream.BaseURL should include the repository path context — the handler prepends
// "/v2/{repo}" to the base URL before calling this method.
func (c *OCIClient) GetBlob(ctx context.Context, upstream domain.Upstream, digest string) (*port.UpstreamResponse, error) {
	url := fmt.Sprintf("%s/blobs/%s",
		strings.TrimRight(upstream.BaseURL, "/"),
		digest,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating blob request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUpstreamUnavailable, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, domain.ErrArtifactNotFound
	}

	headers := extractHeaders(resp)

	return &port.UpstreamResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Headers:     headers,
		Body:        resp.Body,
	}, nil
}

// ResolveTag resolves a tag to a digest via HEAD request, falling back to GET.
func (c *OCIClient) ResolveTag(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (string, error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s",
		strings.TrimRight(upstream.BaseURL, "/"),
		repoPath(artifact),
		artifact.Version,
	)

	// Try HEAD first.
	digest, err := c.resolveTagHead(ctx, url)
	if err == nil && digest != "" {
		return digest, nil
	}

	// Fall back to GET.
	return c.resolveTagGet(ctx, url)
}

func (c *OCIClient) resolveTagHead(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating HEAD request: %w", err)
	}
	req.Header.Set("Accept", ociAcceptHeaders)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", domain.ErrUpstreamUnavailable, err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", domain.ErrArtifactNotFound
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header in HEAD response")
	}
	return digest, nil
}

func (c *OCIClient) resolveTagGet(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating GET request: %w", err)
	}
	req.Header.Set("Accept", ociAcceptHeaders)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", domain.ErrUpstreamUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return "", domain.ErrArtifactNotFound
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header in GET response")
	}
	return digest, nil
}

// extractHeaders copies relevant response headers into a map.
func extractHeaders(resp *http.Response) map[string]string {
	interesting := []string{
		"Docker-Content-Digest",
		"Content-Type",
		"Content-Length",
		"ETag",
	}
	headers := make(map[string]string, len(interesting))
	for _, h := range interesting {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	return headers
}
