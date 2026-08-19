package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

var bearerChallengeParamRE = regexp.MustCompile(`([A-Za-z]+)="([^"]*)"`)

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

	//nolint:gosec // G704: req targets the operator/tenant-configured upstream registry; forwarding to it is this proxy's purpose, not attacker-directed SSRF
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

	//nolint:gosec // G704: retry is req.Clone with only the Authorization header changed; same configured-upstream destination as above
	retryResp, err := c.httpClient.Do(retry)
	if err != nil {
		return nil, err
	}
	if canUseCachedBearer && retryResp.StatusCode != http.StatusUnauthorized {
		c.bearerTokens.Set(cacheKey, token, ttl)
	}
	return retryResp, nil
}

func (c *OCIClient) fetchBearerToken(
	ctx context.Context,
	challenge string,
	auth *domain.UpstreamAuth,
) (string, time.Duration, bool, error) {
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
