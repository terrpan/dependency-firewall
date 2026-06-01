package upstream

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const (
	defaultBearerTokenCacheMaxEntries = 128
	defaultBearerTokenTTL             = time.Minute
	bearerTokenExpirySkew             = 15 * time.Second
)

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
