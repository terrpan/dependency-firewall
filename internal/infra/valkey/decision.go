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

// DecisionCache implements port.DecisionCache using Valkey.
type DecisionCache struct {
	client *redis.Client
}

// NewDecisionCache creates a new DecisionCache.
func NewDecisionCache(client *redis.Client) *DecisionCache {
	return &DecisionCache{client: client}
}

func decisionKey(tenantID string, artifact domain.ArtifactIdentity) string {
	return fmt.Sprintf("decision:%s:%s", tenantID, artifact.CacheKey())
}

// Get retrieves a cached decision. Returns domain.ErrCacheMiss if not found.
func (c *DecisionCache) Get(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	data, err := c.client.Get(ctx, decisionKey(tenantID, artifact)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, domain.ErrCacheMiss
		}
		return nil, fmt.Errorf("getting cached decision: %w", err)
	}

	var d domain.Decision
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("unmarshalling cached decision: %w", err)
	}
	return &d, nil
}

// Set stores a decision in the cache with the given TTL.
func (c *DecisionCache) Set(ctx context.Context, decision *domain.Decision, ttl time.Duration) error {
	data, err := json.Marshal(decision)
	if err != nil {
		return fmt.Errorf("marshalling decision for cache: %w", err)
	}

	key := decisionKey(decision.TenantID, decision.Artifact)
	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("setting cached decision: %w", err)
	}
	return nil
}

// Invalidate removes a cached decision.
func (c *DecisionCache) Invalidate(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) error {
	if err := c.client.Del(ctx, decisionKey(tenantID, artifact)).Err(); err != nil {
		return fmt.Errorf("invalidating cached decision: %w", err)
	}
	return nil
}
