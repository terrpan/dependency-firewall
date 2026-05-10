// Package upstream provides clients for fetching content from upstream registries.
package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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

var bearerChallengeParamRE = regexp.MustCompile(`([A-Za-z]+)="([^"]*)"`)

var forwardedResponseHeaders = [...]string{
	"Docker-Content-Digest",
	"Content-Type",
	"Content-Length",
	"ETag",
}

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

// FetchMetadata fetches a manifest from the upstream registry.
func (c *OCIClient) FetchMetadata(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	ref := artifact.Digest
	if ref == "" {
		ref = artifact.Version
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

	resp, err := c.doOCIRequest(req, upstream)
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

// FetchContent streams content from the upstream registry.
// The digest parameter must include the full digest reference (e.g. "sha256:abc123").
// The upstream.BaseURL should include the repository path context — the handler prepends
// "/v2/{repo}" to the base URL before calling this method.
func (c *OCIClient) FetchContent(ctx context.Context, upstream domain.Upstream, digest string) (*port.UpstreamResponse, error) {
	url := fmt.Sprintf("%s/blobs/%s",
		strings.TrimRight(upstream.BaseURL, "/"),
		digest,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating blob request: %w", err)
	}

	resp, err := c.doOCIRequest(req, upstream)
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

// ResolveReference resolves a tag to a digest via HEAD request, falling back to GET.
func (c *OCIClient) ResolveReference(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (string, error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s",
		strings.TrimRight(upstream.BaseURL, "/"),
		repoPath(artifact),
		artifact.Version,
	)

	// Try HEAD first.
	digest, err := c.resolveTagHead(ctx, upstream, url)
	if err == nil && digest != "" {
		return digest, nil
	}

	// Fall back to GET.
	return c.resolveTagGet(ctx, upstream, url)
}

func (c *OCIClient) resolveTagHead(ctx context.Context, upstream domain.Upstream, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating HEAD request: %w", err)
	}
	req.Header.Set("Accept", ociAcceptHeaders)

	resp, err := c.doOCIRequest(req, upstream)
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

func (c *OCIClient) resolveTagGet(ctx context.Context, upstream domain.Upstream, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating GET request: %w", err)
	}
	req.Header.Set("Accept", ociAcceptHeaders)

	resp, err := c.doOCIRequest(req, upstream)
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
	headers := make(map[string]string, len(forwardedResponseHeaders))
	for _, h := range forwardedResponseHeaders {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	return headers
}

func applyRegistryAuth(req *http.Request, auth *domain.UpstreamAuth) {
	if auth == nil {
		return
	}
	switch auth.Type {
	case domain.UpstreamAuthBearerToken:
		req.Header.Set("Authorization", "Bearer "+auth.Secret)
	case domain.UpstreamAuthBasic:
		req.SetBasicAuth(auth.Username, auth.Secret)
	}
}

func (c *OCIClient) doOCIRequest(req *http.Request, upstream domain.Upstream) (*http.Response, error) {
	applyRegistryAuth(req, upstream.Auth)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	token, ok, err := c.fetchBearerToken(req.Context(), resp.Header.Get("WWW-Authenticate"), upstream.Auth)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	if !ok {
		return resp, nil
	}

	resp.Body.Close()

	retry := req.Clone(req.Context())
	retry.Header = req.Header.Clone()
	retry.Header.Set("Authorization", "Bearer "+token)

	return c.httpClient.Do(retry)
}

func (c *OCIClient) fetchBearerToken(ctx context.Context, challenge string, auth *domain.UpstreamAuth) (string, bool, error) {
	params, ok := parseBearerChallenge(challenge)
	if !ok {
		return "", false, nil
	}

	realm, ok := params["realm"]
	if !ok || realm == "" {
		return "", false, fmt.Errorf("bearer challenge missing realm")
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", false, fmt.Errorf("parsing bearer token realm: %w", err)
	}

	query := tokenURL.Query()
	if service := params["service"]; service != "" {
		query.Set("service", service)
	}
	if scope := params["scope"]; scope != "" {
		query.Set("scope", scope)
	}
	tokenURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", false, fmt.Errorf("creating bearer token request: %w", err)
	}
	if auth != nil && auth.Type == domain.UpstreamAuthBasic {
		req.SetBasicAuth(auth.Username, auth.Secret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("unexpected bearer token status: %d", resp.StatusCode)
	}

	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", false, fmt.Errorf("decoding bearer token response: %w", err)
	}

	if payload.Token != "" {
		return payload.Token, true, nil
	}
	if payload.AccessToken != "" {
		return payload.AccessToken, true, nil
	}

	return "", false, fmt.Errorf("bearer token response missing token")
}

func parseBearerChallenge(challenge string) (map[string]string, bool) {
	challenge = strings.TrimSpace(challenge)
	if challenge == "" || !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return nil, false
	}

	matches := bearerChallengeParamRE.FindAllStringSubmatch(challenge, -1)
	if len(matches) == 0 {
		return nil, false
	}

	params := make(map[string]string, len(matches))
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		params[strings.ToLower(match[1])] = match[2]
	}

	if len(params) == 0 {
		return nil, false
	}

	return params, true
}
