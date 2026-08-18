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

// DecisionCache implements port.DecisionCache using Valkey.
type DecisionCache struct {
	client valkeygo.Client
}

// NewDecisionCache creates a new DecisionCache.
func NewDecisionCache(client valkeygo.Client) *DecisionCache {
	return &DecisionCache{client: client}
}

func decisionGenerationKey(tenantID string) string {
	return "decision-generation:" + tenantID
}

func decisionKey(
	tenantID string,
	generation int64,
	artifact domain.ArtifactIdentity,
	dependencyContextHash string,
) string {
	if dependencyContextHash == "" {
		dependencyContextHash = "none"
	}
	return "decision:" + tenantID + ":" + strconv.FormatInt(
		generation,
		10,
	) + ":" + dependencyContextHash + ":" + artifact.CacheKey()
}

// Get retrieves a cached decision. Returns domain.ErrCacheMiss if not found.
func (c *DecisionCache) Get(
	ctx context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
	dependencyContextHash string,
) (*domain.Decision, error) {
	generation, err := c.currentGeneration(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	data, err := c.client.Do(ctx, c.client.B().Get().Key(decisionKey(tenantID, generation, artifact, dependencyContextHash)).Build()).
		AsBytes()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
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

	dependencyContextHash := ""
	if decision.DependencyContext != nil {
		dependencyContextHash = decision.DependencyContext.Normalize().ContextHash
	}
	key := decisionKey(decision.TenantID, generation, decision.Artifact, dependencyContextHash)
	cmd := c.client.B().Set().Key(key).Value(valkeygo.BinaryString(data))
	if ttl > 0 {
		if err := c.client.Do(ctx, cmd.Px(ttl).Build()).Error(); err != nil {
			return fmt.Errorf("setting cached decision: %w", err)
		}
		return nil
	}
	if err := c.client.Do(ctx, cmd.Build()).Error(); err != nil {
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

	if err := c.client.Do(ctx, c.client.B().Del().Key(decisionKey(tenantID, generation, artifact, "")).Build()).
		Error(); err != nil {
		return fmt.Errorf("invalidating cached decision: %w", err)
	}
	return nil
}

// InvalidateTenant invalidates all cached decisions for a tenant by bumping the
// tenant cache generation.
func (c *DecisionCache) InvalidateTenant(ctx context.Context, tenantID string) error {
	if err := c.client.Do(ctx, c.client.B().Incr().Key(decisionGenerationKey(tenantID)).Build()).Error(); err != nil {
		return fmt.Errorf("invalidating tenant decision cache: %w", err)
	}
	return nil
}

func (c *DecisionCache) currentGeneration(ctx context.Context, tenantID string) (int64, error) {
	value, err := c.client.Do(ctx, c.client.B().Get().Key(decisionGenerationKey(tenantID)).Build()).ToString()
	if err == nil {
		generation, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("parsing decision cache generation: %w", parseErr)
		}
		return generation, nil
	}
	if valkeygo.IsValkeyNil(err) {
		return 0, nil
	}
	return 0, fmt.Errorf("getting decision cache generation: %w", err)
}
