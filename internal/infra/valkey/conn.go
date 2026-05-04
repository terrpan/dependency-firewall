// Package valkey provides Valkey (Redis-compatible) cache implementations.
package valkey

import (
	"context"
	"fmt"

	valkeygo "github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeyotel"

	"github.com/danielterry/dependency-firewall/internal/config"
)

// Connect creates a new Valkey client from the given configuration.
func Connect(_ context.Context, cfg config.ValkeyConfig) (valkeygo.Client, error) {
	client, err := valkeyotel.NewClient(valkeygo.ClientOption{
		InitAddress: []string{cfg.Addr},
		Password:    cfg.Password,
		SelectDB:    cfg.DB,
	})
	if err != nil {
		return nil, fmt.Errorf("creating valkey client: %w", err)
	}
	return client, nil
}

// HealthCheck verifies the Valkey connection is alive.
func HealthCheck(ctx context.Context, client valkeygo.Client) error {
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		return fmt.Errorf("valkey health check: %w", err)
	}
	return nil
}
