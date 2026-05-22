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
	"sync"
	"time"

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

const (
	defaultBearerTokenCacheMaxEntries = 128
	defaultBearerTokenTTL             = time.Minute
	bearerTokenExpirySkew             = 15 * time.Second
)

var forwardedResponseHeaders = [...]string{
	"Docker-Content-Digest",
	"Content-Type",
	"Content-Length",
	"ETag",
}

// OCIClient implements port.UpstreamClient for OCI-compatible registries.
type OCIClient struct {
	httpClient     *http.Client
	secretResolver authSecretResolver
	bearerTokens   *bearerTokenCache
}

type authSecretResolver interface {
	ResolveSecret([]byte) ([]byte, error)
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

func (c *OCIClient) applyRegistryAuth(req *http.Request, auth *domain.UpstreamAuth) error {
	if auth == nil {
		return nil
	}
	secret, err := c.resolveAuthSecret(auth)
	if err != nil {
		return err
	}

	switch auth.Type {
	case domain.UpstreamAuthBearerToken:
		req.Header.Set("Authorization", "Bearer "+string(secret))
	case domain.UpstreamAuthBasic:
		req.SetBasicAuth(auth.Username, string(secret))
	}
	return nil
}

func (c *OCIClient) doOCIRequest(req *http.Request, upstream domain.Upstream) (*http.Response, error) {
	cacheKey, canUseCachedBearer := bearerTokenCacheKey(req, upstream)
	if canUseCachedBearer {
		if token, ok := c.bearerTokens.Get(cacheKey); ok {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if err := c.applyRegistryAuth(req, upstream.Auth); err != nil {
			return nil, err
		}
	} else {
		if err := c.applyRegistryAuth(req, upstream.Auth); err != nil {
			return nil, err
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	token, ttl, ok, err := c.fetchBearerToken(req.Context(), resp.Header.Get("WWW-Authenticate"), upstream.Auth)
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

	retryResp, err := c.httpClient.Do(retry)
	if err != nil {
		return nil, err
	}
	if canUseCachedBearer && retryResp.StatusCode != http.StatusUnauthorized {
		c.bearerTokens.Set(cacheKey, token, ttl)
	}
	return retryResp, nil
}

func (c *OCIClient) fetchBearerToken(ctx context.Context, challenge string, auth *domain.UpstreamAuth) (string, time.Duration, bool, error) {
	params, ok := parseBearerChallenge(challenge)
	if !ok {
		return "", 0, false, nil
	}

	realm, ok := params["realm"]
	if !ok || realm == "" {
		return "", 0, false, fmt.Errorf("bearer challenge missing realm")
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", 0, false, fmt.Errorf("parsing bearer token realm: %w", err)
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
		return "", 0, false, fmt.Errorf("creating bearer token request: %w", err)
	}
	if auth != nil && auth.Type == domain.UpstreamAuthBasic {
		secret, err := c.resolveAuthSecret(auth)
		if err != nil {
			return "", 0, false, err
		}
		req.SetBasicAuth(auth.Username, string(secret))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, false, fmt.Errorf("unexpected bearer token status: %d", resp.StatusCode)
	}

	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", 0, false, fmt.Errorf("decoding bearer token response: %w", err)
	}

	ttl := defaultBearerTokenTTL
	if payload.ExpiresIn > 0 {
		ttl = time.Duration(payload.ExpiresIn) * time.Second
	}
	if payload.Token != "" {
		return payload.Token, ttl, true, nil
	}
	if payload.AccessToken != "" {
		return payload.AccessToken, ttl, true, nil
	}

	return "", 0, false, fmt.Errorf("bearer token response missing token")
}

func (c *OCIClient) resolveAuthSecret(auth *domain.UpstreamAuth) ([]byte, error) {
	if auth == nil || auth.Secret == "" {
		return nil, nil
	}
	raw := []byte(auth.Secret)
	if c.secretResolver == nil {
		return raw, nil
	}
	secret, err := c.secretResolver.ResolveSecret(raw)
	if err != nil {
		return nil, fmt.Errorf("resolving upstream auth secret: %w", err)
	}
	return secret, nil
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

func bearerTokenCacheKey(req *http.Request, upstream domain.Upstream) (string, bool) {
	if req == nil || req.URL == nil {
		return "", false
	}
	auth := upstream.Auth
	if auth != nil && auth.Type == domain.UpstreamAuthBearerToken {
		return "", false
	}

	repository, ok := repositoryFromOCIPath(req.URL.Path)
	if !ok {
		return "", false
	}

	principal := "anonymous"
	if auth != nil {
		principal = string(auth.Type) + ":" + auth.Username
	}

	return upstream.TenantID + "|" + upstream.ID + "|" + req.URL.Scheme + "://" + req.URL.Host + "|" + repository + "|" + principal, true
}

func repositoryFromOCIPath(path string) (string, bool) {
	const prefix = "/v2/"
	after, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return "", false
	}
	for _, marker := range []string{"/manifests/", "/blobs/"} {
		repository, _, found := strings.Cut(after, marker)
		if found && repository != "" {
			return repository, true
		}
	}
	return "", false
}

type bearerTokenCache struct {
	mu         sync.Mutex
	now        func() time.Time
	maxEntries int
	entries    map[string]cachedBearerToken
}

type cachedBearerToken struct {
	token     string
	expiresAt time.Time
}

func newBearerTokenCache(maxEntries int) *bearerTokenCache {
	if maxEntries <= 0 {
		maxEntries = defaultBearerTokenCacheMaxEntries
	}
	return &bearerTokenCache{
		now:        time.Now,
		maxEntries: maxEntries,
		entries:    make(map[string]cachedBearerToken),
	}
}

func (c *bearerTokenCache) Get(key string) (string, bool) {
	if c == nil || key == "" {
		return "", false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return "", false
	}
	if !entry.expiresAt.After(c.now()) {
		delete(c.entries, key)
		return "", false
	}
	return entry.token, true
}

func (c *bearerTokenCache) Set(key, token string, ttl time.Duration) {
	if c == nil || key == "" || token == "" {
		return
	}
	if ttl <= 0 {
		ttl = defaultBearerTokenTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if len(c.entries) >= c.maxEntries {
		for entryKey, entry := range c.entries {
			if !entry.expiresAt.After(now) {
				delete(c.entries, entryKey)
			}
		}
	}
	if len(c.entries) >= c.maxEntries {
		c.entries = make(map[string]cachedBearerToken)
	}

	expiresAt := now.Add(ttl)
	if ttl > bearerTokenExpirySkew {
		expiresAt = expiresAt.Add(-bearerTokenExpirySkew)
	}
	c.entries[key] = cachedBearerToken{
		token:     token,
		expiresAt: expiresAt,
	}
}
