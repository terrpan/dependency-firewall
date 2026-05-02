package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/api"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
	npmdelivery "github.com/danielterry/dependency-firewall/internal/delivery/npm"
	ocidelivery "github.com/danielterry/dependency-firewall/internal/delivery/oci"
	"github.com/danielterry/dependency-firewall/internal/infra/enrichment"
	"github.com/danielterry/dependency-firewall/internal/infra/npm"
	"github.com/danielterry/dependency-firewall/internal/infra/ocicache"
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
	policyRevisionRepo := postgres.NewPolicyRevisionRepository(pool)
	decisionRepo := postgres.NewDecisionRepository(pool)
	upstreamRepo := postgres.NewUpstreamRepository(pool)

	// Instantiate caches.
	decisionCache := valkey.NewDecisionCache(valkeyClient)
	metadataCache := valkey.NewMetadataCache(valkeyClient)

	// Create enrichers: OSV for vulnerabilities, npm for publish dates.
	osvEnricher := osv.NewClient(&http.Client{}, logger)
	npmEnricher := npm.NewMetadataEnricher(&http.Client{}, logger)
	enricher := enrichment.NewCompositeEnricher(logger, osvEnricher, npmEnricher)
	enrichmentService := service.NewEnrichmentService(enricher, metadataCache, logger)

	// Create upstream client.
	baseOCIClient := upstream.NewOCIClient(newOCIHTTPClient())
	var ociClient port.UpstreamClient = baseOCIClient
	if cfg.OCICache.Enabled {
		artifactCache, err := newOCIArtifactCache(cfg.OCICache)
		if err != nil {
			return fmt.Errorf("creating OCI cache: %w", err)
		}
		ociClient = upstream.NewCachedOCIClient(baseOCIClient, artifactCache, logger)
	}

	// Create policy evaluator and shared access service.
	evaluator := policy.NewEvaluator()
	accessService := service.NewAccessService(
		policyRepo,
		decisionRepo,
		decisionCache,
		enrichmentService,
		evaluator,
		ociClient,
		upstreamRepo,
		logger,
	)

	// Create OCI handler.
	ociHandler := ocidelivery.NewRegistryHandler(accessService, ociClient, upstreamRepo, logger)

	// Create npm handler.
	npmClient := upstream.NewNPMClient(&http.Client{Timeout: 30 * time.Second})
	npmHandler := npmdelivery.NewRegistryHandler(accessService, npmClient, upstreamRepo, logger)

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
	controlPlaneAPI := api.NewControlPlaneAPI(mux, ver)

	// Health check (no middleware).
	healthHandler.RegisterHumaRoutes(controlPlaneAPI)

	// Register OCI routes.
	ociMux := http.NewServeMux()
	ociHandler.RegisterRoutes(ociMux)

	// Register npm routes.
	npmMux := http.NewServeMux()
	npmHandler.RegisterRoutes(npmMux)

	// Apply middleware chain: recovery -> logging -> tenant resolution -> handler.
	var ociWrapped http.Handler = ociMux
	ociWrapped = tenantResolver.Middleware(ociWrapped)
	ociWrapped = middleware.OCITenantFromHost()(ociWrapped)
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
	tenantService := service.NewTenantService(tenantRepo)
	policyService := service.NewPolicyService(policyRepo, policyRevisionRepo, decisionCache, upstreamRepo)
	cacheService := service.NewCacheService(decisionCache, metadataCache)
	upstreamService := service.NewUpstreamService(upstreamRepo, policyRepo)
	evaluationService := service.NewEvaluationService(decisionRepo)

	tenantHandler := api.NewTenantHandler(tenantService, logger)
	policyHandler := api.NewPolicyHandler(policyService, logger)
	cacheHandler := api.NewCacheHandler(cacheService, logger)
	upstreamHandler := api.NewUpstreamHandler(upstreamService, logger)
	evaluationHandler := api.NewEvaluationHandler(evaluationService, logger)

	tenantHandler.RegisterHumaRoutes(controlPlaneAPI)
	policyHandler.RegisterHumaRoutes(controlPlaneAPI)
	cacheHandler.RegisterHumaRoutes(controlPlaneAPI)
	upstreamHandler.RegisterHumaRoutes(controlPlaneAPI)
	evaluationHandler.RegisterHumaRoutes(controlPlaneAPI)

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

func newOCIHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second
	transport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext

	return &http.Client{Transport: transport}
}

func newOCIArtifactCache(cfg config.OCICacheConfig) (port.OCIArtifactCache, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "disk":
		return ocicache.NewDiskCache(ocicache.DiskCacheOptions{
			RootDir:    cfg.RootDir,
			MaxBytes:   cfg.MaxBytes,
			MaxAge:     cfg.MaxAge,
			MaxEntries: cfg.MaxEntries,
		})
	case "s3", "gcs":
		return nil, fmt.Errorf("OCI cache backend %q is not implemented yet", cfg.Backend)
	default:
		return nil, fmt.Errorf("unsupported OCI cache backend %q", cfg.Backend)
	}
}
