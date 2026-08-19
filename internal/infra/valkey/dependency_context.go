package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DependencyContextCache implements port.DependencyContextCache using Valkey.
type DependencyContextCache struct {
	client valkeygo.Client
}

// NewDependencyContextCache creates a new DependencyContextCache.
func NewDependencyContextCache(client valkeygo.Client) *DependencyContextCache {
	return &DependencyContextCache{client: client}
}

func dependencyContextKey(key domain.DependencyContextSummaryKey) string {
	return "dependency-context:" + key.TenantID + ":" + key.UpstreamID + ":" + key.Artifact.CacheKey()
}

// Get retrieves a cached dependency context. Returns domain.ErrCacheMiss if not found.
func (c *DependencyContextCache) Get(
	ctx context.Context,
	key domain.DependencyContextSummaryKey,
) (*domain.DependencyContext, error) {
	data, err := c.client.Do(ctx, c.client.B().Get().Key(dependencyContextKey(key)).Build()).AsBytes()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return nil, domain.ErrCacheMiss
		}
		return nil, fmt.Errorf("getting cached dependency context: %w", err)
	}

	var dependencyContext domain.DependencyContext
	if err := json.Unmarshal(data, &dependencyContext); err != nil {
		return nil, fmt.Errorf("unmarshalling cached dependency context: %w", err)
	}
	dependencyContext = dependencyContext.Normalize()
	return &dependencyContext, nil
}

// Set stores a dependency context in the cache with the given TTL.
func (c *DependencyContextCache) Set(
	ctx context.Context,
	key domain.DependencyContextSummaryKey,
	dependencyContext domain.DependencyContext,
	ttl time.Duration,
) error {
	dependencyContext = dependencyContext.Normalize()
	data, err := json.Marshal(dependencyContext)
	if err != nil {
		return fmt.Errorf("marshalling dependency context for cache: %w", err)
	}

	cmd := c.client.B().Set().Key(dependencyContextKey(key)).Value(valkeygo.BinaryString(data))
	if ttl > 0 {
		if err := c.client.Do(ctx, cmd.Px(ttl).Build()).Error(); err != nil {
			return fmt.Errorf("setting cached dependency context: %w", err)
		}
		return nil
	}
	if err := c.client.Do(ctx, cmd.Build()).Error(); err != nil {
		return fmt.Errorf("setting cached dependency context: %w", err)
	}
	return nil
}
