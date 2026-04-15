package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// MetadataCache implements port.MetadataCache using Valkey.
type MetadataCache struct {
	client *redis.Client
}

// NewMetadataCache creates a new MetadataCache.
func NewMetadataCache(client *redis.Client) *MetadataCache {
	return &MetadataCache{client: client}
}

func metadataKey(tenantID string, artifact domain.ArtifactIdentity) string {
	return fmt.Sprintf("metadata:%s:%s", tenantID, artifact.CacheKey())
}

// Get retrieves cached artifact metadata. Returns domain.ErrCacheMiss if not found.
func (c *MetadataCache) Get(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	data, err := c.client.Get(ctx, metadataKey(tenantID, artifact)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, domain.ErrCacheMiss
		}
		return nil, fmt.Errorf("getting cached metadata: %w", err)
	}

	var m domain.ArtifactMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshalling cached metadata: %w", err)
	}
	return &m, nil
}

// Set stores artifact metadata in the cache with the given TTL.
func (c *MetadataCache) Set(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity, metadata *domain.ArtifactMetadata, ttl time.Duration) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata for cache: %w", err)
	}

	key := metadataKey(tenantID, artifact)
	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("setting cached metadata: %w", err)
	}
	return nil
}
