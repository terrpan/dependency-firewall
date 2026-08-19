// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"fmt"
	"math"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/config"
)

// boundedPoolSize narrows an operator-supplied pool size to pgx's int32 field.
// Without the bound, a value above math.MaxInt32 wraps to a negative pool size,
// which pgx rejects far away from the config that caused it.
func boundedPoolSize(size int) int32 {
	switch {
	case size < 0:
		return 0
	case size > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(size)
	}
}

// Connect creates a new PostgreSQL connection pool from the given configuration.
func Connect(ctx context.Context, cfg config.DatabaseConfig, traceCfg config.SQLTracingConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parsing database DSN: %w", err)
	}

	tracingOptions := make([]otelpgx.Option, 0, 2)
	if traceCfg.TrimSQLInSpanName {
		tracingOptions = append(tracingOptions, otelpgx.WithTrimSQLInSpanName())
	}
	if traceCfg.DisableSQLStatementInAttributes {
		tracingOptions = append(tracingOptions, otelpgx.WithDisableSQLStatementInAttributes())
	}

	poolCfg.MaxConns = boundedPoolSize(cfg.MaxOpenConns)
	poolCfg.MinConns = boundedPoolSize(cfg.MaxIdleConns)
	poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
	poolCfg.ConnConfig.Tracer = otelpgx.NewTracer(tracingOptions...)

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return pool, nil
}

// HealthCheck verifies the database connection is alive.
func HealthCheck(ctx context.Context, pool *pgxpool.Pool) error {
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database health check: %w", err)
	}
	return nil
}
