// Package valkey provides Valkey (Redis-compatible) cache implementations.
package valkey

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/danielterry/dependency-firewall/internal/config"
)

// Connect creates a new Valkey client from the given configuration.
func Connect(_ context.Context, cfg config.ValkeyConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	return client, nil
}

// HealthCheck verifies the Valkey connection is alive.
func HealthCheck(ctx context.Context, client *redis.Client) error {
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("valkey health check: %w", err)
	}
	return nil
}
