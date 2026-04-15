package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/api"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
	npmdelivery "github.com/danielterry/dependency-firewall/internal/delivery/npm"
	ocidelivery "github.com/danielterry/dependency-firewall/internal/delivery/oci"
	"github.com/danielterry/dependency-firewall/internal/infra/enrichment"
	"github.com/danielterry/dependency-firewall/internal/infra/npm"
	"github.com/danielterry/dependency-firewall/internal/infra/osv"
	"github.com/danielterry/dependency-firewall/internal/infra/postgres"
	"github.com/danielterry/dependency-firewall/internal/infra/upstream"
	"github.com/danielterry/dependency-firewall/internal/infra/valkey"
	"github.com/danielterry/dependency-firewall/migrations"
)

// Ldflags variables — automatically set by ko via VCS info, no manual -X needed
var (
	ldVersion   = "dev"
	ldCommit    = "unknown"
	ldBuildTime = "unknown"
)

// buildInfo extracts version metadata from Go's embedded build info (VCS)
// and falls back to ldflags if VCS info is unavailable.
// ko (https://ko.build) and `go build` both populate VCS settings automatically,
// but in containerized builds without .git, ldflags provide the fallback.
func buildInfo() (version, commit, buildTime string) {
	version = ldVersion
	commit = ldCommit
	buildTime = ldBuildTime

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	// VCS info takes precedence over ldflags
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.time":
			buildTime = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				commit += "-dirty"
			}
		}
	}
	return
}

// dbHealthChecker adapts *pgxpool.Pool to service.HealthChecker.
type dbHealthChecker struct{ pool *pgxpool.Pool }

func (c *dbHealthChecker) Ping(ctx context.Context) error { return c.pool.Ping(ctx) }

// cacheHealthChecker adapts *redis.Client to service.HealthChecker.
type cacheHealthChecker struct{ client *redis.Client }

func (c *cacheHealthChecker) Ping(ctx context.Context) error { return c.client.Ping(ctx).Err() }

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger := config.SetupLogging(cfg.Log)
	slog.SetDefault(logger)

	logger.Info("starting dependency-firewall",
		"port", cfg.Server.Port,
		"log_level", cfg.Log.Level,
	)

	ctx := context.Background()

	// Run database migrations.
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}
	// The pgx/v5 migrate driver registers as "pgx5", so rewrite the DSN scheme.
	migrateDSN := strings.Replace(cfg.Database.DSN, "postgres://", "pgx5://", 1)
	migrateDSN = strings.Replace(migrateDSN, "postgresql://", "pgx5://", 1)
	m, err := migrate.NewWithSourceInstance("iofs", source, migrateDSN)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		return fmt.Errorf("closing migration source: %w", srcErr)
	}
	if dbErr != nil {
		return fmt.Errorf("closing migration db: %w", dbErr)
	}
	logger.Info("database migrations applied")

	// Create PostgreSQL connection pool.
	pool, err := postgres.Connect(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	// Create Valkey client.
	valkeyClient, err := valkey.Connect(ctx, cfg.Valkey)
	if err != nil {
		return fmt.Errorf("connecting to valkey: %w", err)
	}
	defer valkeyClient.Close()

	// Instantiate repositories.
	tenantRepo := postgres.NewTenantRepository(pool)
	policyRepo := postgres.NewPolicyRepository(pool)
	decisionRepo := postgres.NewDecisionRepository(pool)
	upstreamRepo := postgres.NewUpstreamRepository(pool)

	// Instantiate caches.
	decisionCache := valkey.NewDecisionCache(valkeyClient)
	metadataCache := valkey.NewMetadataCache(valkeyClient)

	// Create enrichers: OSV for vulnerabilities, npm for publish dates.
	osvEnricher := osv.NewClient(&http.Client{}, logger)
	npmEnricher := npm.NewMetadataEnricher(&http.Client{}, logger)
	enricher := enrichment.NewCompositeEnricher(logger, osvEnricher, npmEnricher)

	// Create upstream client.
	ociClient := upstream.NewOCIClient(&http.Client{Timeout: 30 * time.Second})

	// Create policy evaluator and proxy service.
	evaluator := policy.NewEvaluator()
	proxyService := service.NewProxyService(
		policyRepo,
		decisionRepo,
		decisionCache,
		metadataCache,
		enricher,
		evaluator,
		ociClient,
		upstreamRepo,
		logger,
	)

	// Create OCI handler.
	ociHandler := ocidelivery.NewHandler(proxyService, ociClient, upstreamRepo, logger)

	// Create npm handler.
	npmClient := upstream.NewNPMClient(&http.Client{Timeout: 30 * time.Second})
	npmHandler := npmdelivery.NewHandler(proxyService, npmClient, upstreamRepo, logger)

	// Build middleware chain.
	tenantResolver := middleware.NewTenantResolver(tenantRepo)

	// Create health service and handler.
	ver, commit, buildTime := buildInfo()
	healthService := service.NewHealthService(
		"dependency-firewall", ver, commit, buildTime,
		&dbHealthChecker{pool: pool},
		&cacheHealthChecker{client: valkeyClient},
		logger,
	)
	healthHandler := api.NewHealthHandler(healthService, logger)

	mux := http.NewServeMux()

	// Health check (no middleware).
	healthHandler.RegisterRoutes(mux)

	// Register OCI routes.
	ociMux := http.NewServeMux()
	ociHandler.RegisterRoutes(ociMux)

	// Register npm routes.
	npmMux := http.NewServeMux()
	npmHandler.RegisterRoutes(npmMux)

	// Apply middleware chain: recovery -> logging -> tenant resolution -> handler.
	var ociWrapped http.Handler = ociMux
	ociWrapped = tenantResolver.Middleware(ociWrapped)
	ociWrapped = middleware.RequestLogging(logger)(ociWrapped)
	ociWrapped = middleware.Recovery(logger)(ociWrapped)

	var npmWrapped http.Handler = npmMux
	npmWrapped = tenantResolver.Middleware(npmWrapped)
	npmWrapped = middleware.NPMTenantFromPath()(npmWrapped) // Extract tenant from /npm/t/{id}/... (runs before tenant resolver)
	npmWrapped = middleware.RequestLogging(logger)(npmWrapped)
	npmWrapped = middleware.Recovery(logger)(npmWrapped)

	mux.Handle("/v2/", ociWrapped)
	mux.Handle("/npm/", npmWrapped)

	// Register control plane API routes (no tenant middleware wrapping).
	tenantHandler := api.NewTenantHandler(tenantRepo, logger)
	policyHandler := api.NewPolicyHandler(policyRepo, logger)
	upstreamHandler := api.NewUpstreamHandler(upstreamRepo, logger)
	evaluationHandler := api.NewEvaluationHandler(decisionRepo, logger)

	tenantHandler.RegisterRoutes(mux)
	policyHandler.RegisterRoutes(mux)
	upstreamHandler.RegisterRoutes(mux)
	evaluationHandler.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Listen for shutdown signals in a separate goroutine.
	shutdownErr := make(chan error, 1)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("received shutdown signal", "signal", sig.String())

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		shutdownErr <- srv.Shutdown(ctx)
	}()

	logger.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}

	if err := <-shutdownErr; err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	logger.Info("shutdown complete")
	return nil
}
