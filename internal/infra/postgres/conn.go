// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/config"
)

// Connect creates a new PostgreSQL connection pool from the given configuration.
func Connect(ctx context.Context, cfg config.DatabaseConfig, traceCfg config.SQLTracingConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parsing database DSN: %w", err)
	}

	tracingOptions := []otelpgx.Option{}
	if traceCfg.TrimSQLInSpanName {
		tracingOptions = append(tracingOptions, otelpgx.WithTrimSQLInSpanName())
	}
	if traceCfg.DisableSQLStatementInAttributes {
		tracingOptions = append(tracingOptions, otelpgx.WithDisableSQLStatementInAttributes())
	}

	// poolCfg.ConnConfig.Tracer = otelpgx.NewTracer(tracingOptions...)

	poolCfg.MaxConns = int32(cfg.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.MaxIdleConns)
	poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
	poolCfg.ConnConfig.Tracer = otelpgx.NewTracer(tracingOptions...)
		// otelpgx.WithTrimSQLInSpanName(),
		// otelpgx.WithDisableSQLStatementInAttributes(),
	// )

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
