package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// MetadataCache implements port.MetadataCache using Valkey.
type MetadataCache struct {
	client valkeygo.Client
}

// NewMetadataCache creates a new MetadataCache.
func NewMetadataCache(client valkeygo.Client) *MetadataCache {
	return &MetadataCache{client: client}
}

func metadataGenerationKey(tenantID string) string {
	return "metadata-generation:" + tenantID
}

func metadataKey(tenantID string, generation int64, artifact domain.ArtifactIdentity) string {
	return "metadata:" + tenantID + ":" + strconv.FormatInt(generation, 10) + ":" + artifact.CacheKey()
}

// Get retrieves cached artifact metadata. Returns domain.ErrCacheMiss if not found.
func (c *MetadataCache) Get(
	ctx context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.ArtifactMetadata, error) {
	generation, err := c.currentGeneration(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	data, err := c.client.Do(ctx, c.client.B().Get().Key(metadataKey(tenantID, generation, artifact)).Build()).AsBytes()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
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
func (c *MetadataCache) Set(
	ctx context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
	metadata *domain.ArtifactMetadata,
	ttl time.Duration,
) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata for cache: %w", err)
	}

	generation, err := c.currentGeneration(ctx, tenantID)
	if err != nil {
		return err
	}

	key := metadataKey(tenantID, generation, artifact)
	cmd := c.client.B().Set().Key(key).Value(valkeygo.BinaryString(data))
	if ttl > 0 {
		if err := c.client.Do(ctx, cmd.Px(ttl).Build()).Error(); err != nil {
			return fmt.Errorf("setting cached metadata: %w", err)
		}
		return nil
	}
	if err := c.client.Do(ctx, cmd.Build()).Error(); err != nil {
		return fmt.Errorf("setting cached metadata: %w", err)
	}
	return nil
}

// InvalidateTenant invalidates all cached metadata for a tenant by bumping the
// tenant cache generation.
func (c *MetadataCache) InvalidateTenant(ctx context.Context, tenantID string) error {
	if err := c.client.Do(ctx, c.client.B().Incr().Key(metadataGenerationKey(tenantID)).Build()).Error(); err != nil {
		return fmt.Errorf("invalidating tenant metadata cache: %w", err)
	}
	return nil
}

func (c *MetadataCache) currentGeneration(ctx context.Context, tenantID string) (int64, error) {
	value, err := c.client.Do(ctx, c.client.B().Get().Key(metadataGenerationKey(tenantID)).Build()).ToString()
	if err == nil {
		generation, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("parsing metadata cache generation: %w", parseErr)
		}
		return generation, nil
	}
	if valkeygo.IsValkeyNil(err) {
		return 0, nil
	}
	return 0, fmt.Errorf("getting metadata cache generation: %w", err)
}
