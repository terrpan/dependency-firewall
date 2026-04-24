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

func decisionGenerationKey(tenantID string) string {
	return fmt.Sprintf("decision-generation:%s", tenantID)
}

func decisionKey(tenantID string, generation int64, artifact domain.ArtifactIdentity) string {
	return fmt.Sprintf("decision:%s:%d:%s", tenantID, generation, artifact.CacheKey())
}

// Get retrieves a cached decision. Returns domain.ErrCacheMiss if not found.
func (c *DecisionCache) Get(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	generation, err := c.currentGeneration(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	data, err := c.client.Get(ctx, decisionKey(tenantID, generation, artifact)).Bytes()
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

	generation, err := c.currentGeneration(ctx, decision.TenantID)
	if err != nil {
		return err
	}

	key := decisionKey(decision.TenantID, generation, decision.Artifact)
	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("setting cached decision: %w", err)
	}
	return nil
}

// Invalidate removes a cached decision.
func (c *DecisionCache) Invalidate(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) error {
	generation, err := c.currentGeneration(ctx, tenantID)
	if err != nil {
		return err
	}

	if err := c.client.Del(ctx, decisionKey(tenantID, generation, artifact)).Err(); err != nil {
		return fmt.Errorf("invalidating cached decision: %w", err)
	}
	return nil
}

// InvalidateTenant invalidates all cached decisions for a tenant by bumping the
// tenant cache generation.
func (c *DecisionCache) InvalidateTenant(ctx context.Context, tenantID string) error {
	if err := c.client.Incr(ctx, decisionGenerationKey(tenantID)).Err(); err != nil {
		return fmt.Errorf("invalidating tenant decision cache: %w", err)
	}
	return nil
}

func (c *DecisionCache) currentGeneration(ctx context.Context, tenantID string) (int64, error) {
	generation, err := c.client.Get(ctx, decisionGenerationKey(tenantID)).Int64()
	if err == nil {
		return generation, nil
	}
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return 0, fmt.Errorf("getting decision cache generation: %w", err)
}
