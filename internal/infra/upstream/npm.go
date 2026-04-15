package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// NPMClient implements port.UpstreamClient for npm registries.
type NPMClient struct {
	httpClient *http.Client
}

// NewNPMClient creates a new NPMClient.
func NewNPMClient(httpClient *http.Client) *NPMClient {
	return &NPMClient{httpClient: httpClient}
}

// npmPackagePath builds the URL-encoded package path from an artifact identity.
// Scoped packages (namespace starting with "@") are encoded as %40scope%2Fname.
func npmPackagePath(artifact domain.ArtifactIdentity) string {
	if strings.HasPrefix(artifact.Namespace, "@") {
		return url.PathEscape(artifact.Namespace + "/" + artifact.Name)
	}
	return artifact.Name
}

// GetManifest fetches package metadata from the npm registry.
// If the artifact has a semver version, it fetches that specific version;
// otherwise it fetches the full package document.
func (c *NPMClient) GetManifest(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	base := strings.TrimRight(upstream.BaseURL, "/")
	pkgPath := npmPackagePath(artifact)

	reqURL := base + "/" + pkgPath
	if artifact.Version != "" {
		reqURL += "/" + artifact.Version
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating npm manifest request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

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

// GetBlob fetches a tarball from the npm registry.
// The digest parameter is unused for npm; the URL is constructed from the upstream
// base URL combined with the package name and version convention:
// {baseURL}/{packagePath}/-/{name}-{version}.tgz
//
// For npm, the caller is expected to encode the tarball reference in the digest
// string as "name/version" so the client can reconstruct the tarball URL.
func (c *NPMClient) GetBlob(ctx context.Context, upstream domain.Upstream, digest string) (*port.UpstreamResponse, error) {
	reqURL := strings.TrimRight(upstream.BaseURL, "/") + "/" + digest

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating npm tarball request: %w", err)
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

// npmDistTags is the minimal structure needed to read dist-tags from npm metadata.
type npmDistTags struct {
	DistTags map[string]string `json:"dist-tags"`
}

// ResolveTag resolves an npm dist-tag (e.g. "latest") to a semver version string
// by fetching the full package metadata and reading .dist-tags.{tag}.
func (c *NPMClient) ResolveTag(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (string, error) {
	base := strings.TrimRight(upstream.BaseURL, "/")
	pkgPath := npmPackagePath(artifact)
	reqURL := base + "/" + pkgPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating npm tag resolve request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

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

	var meta npmDistTags
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("decoding npm metadata: %w", err)
	}

	tag := artifact.Version
	if tag == "" {
		tag = "latest"
	}

	version, ok := meta.DistTags[tag]
	if !ok {
		return "", fmt.Errorf("dist-tag %q not found in package metadata", tag)
	}

	return version, nil
}
