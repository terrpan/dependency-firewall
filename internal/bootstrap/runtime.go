package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"google.golang.org/grpc"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	apidelivery "github.com/danielterry/dependency-firewall/internal/delivery/api"
	"github.com/danielterry/dependency-firewall/internal/delivery/bundlegrpc"
	healthdelivery "github.com/danielterry/dependency-firewall/internal/delivery/health"
	"github.com/danielterry/dependency-firewall/internal/delivery/ingestgrpc"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
	npmdelivery "github.com/danielterry/dependency-firewall/internal/delivery/npm"
	ocidelivery "github.com/danielterry/dependency-firewall/internal/delivery/oci"
	auditinfra "github.com/danielterry/dependency-firewall/internal/infra/audit"
	bundleinfra "github.com/danielterry/dependency-firewall/internal/infra/bundle"
	"github.com/danielterry/dependency-firewall/internal/infra/enrichment"
	ingestinfra "github.com/danielterry/dependency-firewall/internal/infra/ingest"
	"github.com/danielterry/dependency-firewall/internal/infra/npm"
	"github.com/danielterry/dependency-firewall/internal/infra/ocicache"
	"github.com/danielterry/dependency-firewall/internal/infra/osv"
	"github.com/danielterry/dependency-firewall/internal/infra/postgres"
	"github.com/danielterry/dependency-firewall/internal/infra/upstream"
	"github.com/danielterry/dependency-firewall/internal/infra/valkey"
	"github.com/danielterry/dependency-firewall/migrations"
)

// BuildInfo contains runtime version metadata.
type BuildInfo struct {
	ServiceName string
	Version     string
	Commit      string
	BuildTime   string
}

// Run starts the selected runtime mode inside the single firewall binary.
func Run(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	switch cfg.Runtime.Mode {
	case config.RuntimeModeControlPlane:
		info.ServiceName = "dependency-firewall-control-plane"
		return RunControlPlane(ctx, cfg, logger, info)
	case config.RuntimeModeProxy:
		info.ServiceName = "dependency-firewall-proxy"
		return RunProxy(ctx, cfg, logger, info)
	default:
		info.ServiceName = "dependency-firewall"
		return RunAllInOne(ctx, cfg, logger, info)
	}
}

type dependencies struct {
	pool         *pgxpool.Pool
	valkeyClient *redis.Client

	tenantRepo         port.TenantRepository
	policyRepo         port.PolicyRepository
	policyRevisionRepo port.PolicyRevisionRepository
	decisionRepo       port.DecisionRepository
	auditRepo          *postgres.AuditEventRepository
	upstreamRepo       port.UpstreamRepository

	decisionCache port.DecisionCache
	metadataCache port.MetadataCache
	enricher      port.Enricher

	auditService      *service.AuditService
	enrichmentService *service.EnrichmentService
	ociClient         port.UpstreamClient
	npmClient         port.UpstreamClient
}

// RunControlPlane starts the control-plane HTTP API and bundle gRPC service.
func RunControlPlane(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	deps, err := openDependencies(ctx, cfg, logger, true, true)
	if err != nil {
		return err
	}
	defer deps.close()

	controlPlaneMux := http.NewServeMux()
	registerControlPlaneRoutes(controlPlaneMux, deps, cfg, logger, info)

	httpServer := newHTTPServer(cfg, controlPlaneMux)

	grpcServer := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	bundlegrpc.NewServer(service.NewBundleService(deps.tenantRepo, deps.policyRepo, deps.upstreamRepo)).Register(grpcServer)
	ingestgrpc.NewServer(service.NewProxyIngestService(deps.decisionRepo, deps.auditRepo)).Register(grpcServer)

	listener, err := net.Listen("tcp", cfg.Bundle.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening for bundle grpc: %w", err)
	}
	defer listener.Close()

	logger.Info("starting control plane",
		"http_addr", httpServer.Addr,
		"bundle_addr", cfg.Bundle.ListenAddr,
	)

	return serve(ctx, logger,
		server{
			name: "control-plane-http",
			start: func() error {
				return httpServer.ListenAndServe()
			},
			shutdown: func(ctx context.Context) error {
				return httpServer.Shutdown(ctx)
			},
		},
		server{
			name: "control-plane-grpc",
			start: func() error {
				return grpcServer.Serve(listener)
			},
			shutdown: func(context.Context) error {
				done := make(chan struct{})
				go func() {
					grpcServer.GracefulStop()
					close(done)
				}()

				select {
				case <-done:
					return nil
				case <-time.After(10 * time.Second):
					grpcServer.Stop()
					return nil
				}
			},
		},
	)
}

// RunProxy starts the proxy HTTP service with a remote bundle client.
func RunProxy(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	deps, err := openDependencies(ctx, cfg, logger, false, false)
	if err != nil {
		return err
	}
	defer deps.close()

	grpcClient, err := bundleinfra.NewGRPCClient(ctx, cfg.Bundle.ControlPlaneAddr)
	if err != nil {
		return err
	}
	defer grpcClient.Close()

	ingestClient, err := ingestinfra.NewGRPCClient(ctx, cfg.Bundle.ControlPlaneAddr)
	if err != nil {
		return err
	}
	defer ingestClient.Close()

	deps.decisionRepo = ingestinfra.NewDecisionRepository(ingestClient)
	auditRecorders := make([]port.AuditEventRecorder, 0, 2)
	if cfg.Audit.Enabled && cfg.Audit.Slog {
		auditRecorders = append(auditRecorders, auditinfra.NewSlogRecorder(logger))
	}
	if cfg.Audit.Enabled && cfg.Audit.Postgres {
		auditRecorders = append(auditRecorders, ingestinfra.NewAuditEventRecorder(ingestClient))
	}
	deps.auditService = service.NewAuditService(
		auditinfra.NewFanoutRecorder(auditRecorders...),
		nil,
		logger,
		cfg.Audit.Enabled,
		parseAuditFailureMode(cfg.Audit.FailureMode),
		parseAuditDetailLevel(cfg.Audit.DetailLevel),
	)
	deps.enrichmentService = service.NewEnrichmentService(deps.enricher, deps.metadataCache, logger, deps.auditService)

	bundleProvider := service.NewCachedBundleProvider(grpcClient, cfg.Bundle.RefreshInterval, logger)
	return runProxyHTTP(ctx, cfg, logger, info, deps, bundleProvider)
}

// RunAllInOne starts the combined local runtime with control-plane HTTP and proxy HTTP.
func RunAllInOne(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	deps, err := openDependencies(ctx, cfg, logger, true, true)
	if err != nil {
		return err
	}
	defer deps.close()

	localBundles := service.NewCachedBundleProvider(
		service.NewBundleService(deps.tenantRepo, deps.policyRepo, deps.upstreamRepo),
		cfg.Bundle.RefreshInterval,
		logger,
	)
	localIngest := service.NewProxyIngestService(deps.decisionRepo, deps.auditRepo)
	proxyDeps := *deps
	proxyDeps.decisionRepo = ingestinfra.NewLocalDecisionRepository(localIngest)
	auditRecorders := make([]port.AuditEventRecorder, 0, 2)
	if cfg.Audit.Enabled && cfg.Audit.Slog {
		auditRecorders = append(auditRecorders, auditinfra.NewSlogRecorder(logger))
	}
	if cfg.Audit.Enabled && cfg.Audit.Postgres {
		auditRecorders = append(auditRecorders, ingestinfra.NewLocalAuditEventRecorder(localIngest))
	}
	proxyDeps.auditService = service.NewAuditService(
		auditinfra.NewFanoutRecorder(auditRecorders...),
		nil,
		logger,
		cfg.Audit.Enabled,
		parseAuditFailureMode(cfg.Audit.FailureMode),
		parseAuditDetailLevel(cfg.Audit.DetailLevel),
	)
	proxyDeps.enrichmentService = service.NewEnrichmentService(proxyDeps.enricher, proxyDeps.metadataCache, logger, proxyDeps.auditService)

	mux := http.NewServeMux()
	registerControlPlaneRoutes(mux, deps, cfg, logger, BuildInfo{
		ServiceName: info.ServiceName,
		Version:     info.Version,
		Commit:      info.Commit,
		BuildTime:   info.BuildTime,
	})
	registerProxyRoutes(mux, &proxyDeps, logger, info, localBundles, false)

	httpServer := newHTTPServer(cfg, mux)
	logger.Info("starting all-in-one firewall",
		"http_addr", httpServer.Addr,
	)

	return serve(ctx, logger, server{
		name: "firewall-http",
		start: func() error {
			return httpServer.ListenAndServe()
		},
		shutdown: func(ctx context.Context) error {
			return httpServer.Shutdown(ctx)
		},
	})
}

func runProxyHTTP(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	info BuildInfo,
	deps *dependencies,
	bundleProvider port.TenantBundleProvider,
) error {
	mux := http.NewServeMux()
	registerProxyRoutes(mux, deps, logger, info, bundleProvider, true)

	httpServer := newHTTPServer(cfg, mux)
	logger.Info("starting proxy",
		"http_addr", httpServer.Addr,
		"bundle_addr", cfg.Bundle.ControlPlaneAddr,
	)

	return serve(ctx, logger, server{
		name: "proxy-http",
		start: func() error {
			return httpServer.ListenAndServe()
		},
		shutdown: func(ctx context.Context) error {
			return httpServer.Shutdown(ctx)
		},
	})
}

func registerControlPlaneRoutes(
	mux *http.ServeMux,
	deps *dependencies,
	cfg *config.Config,
	logger *slog.Logger,
	info BuildInfo,
) {
	controlPlaneAPI := apidelivery.NewControlPlaneAPI(mux, info.Version)

	healthOptions := []service.HealthOption{}
	if cfg.Runtime.Mode == config.RuntimeModeControlPlane {
		if proxyURL := strings.TrimSpace(cfg.Health.ProxyURL); proxyURL != "" {
			healthOptions = append(healthOptions, service.WithProxyStatusChecker(&proxyHealthChecker{
				url:    proxyURL,
				client: &http.Client{Timeout: 3 * time.Second},
			}))
		} else {
			healthOptions = append(healthOptions, service.WithProxyStatus("separate", "proxy runs as a separate service in control-plane mode"))
		}
	}

	healthService := service.NewHealthService(
		info.ServiceName,
		info.Version,
		info.Commit,
		info.BuildTime,
		&dbHealthChecker{pool: deps.pool},
		&cacheHealthChecker{client: deps.valkeyClient},
		logger,
		healthOptions...,
	)

	apidelivery.NewHealthHandler(healthService, logger).RegisterHumaRoutes(controlPlaneAPI)

	tenantService := service.NewTenantService(deps.tenantRepo)
	policyService := service.NewPolicyService(deps.policyRepo, deps.policyRevisionRepo, deps.decisionCache, deps.upstreamRepo)
	cacheService := service.NewCacheService(deps.decisionCache, deps.metadataCache)
	upstreamService := service.NewUpstreamService(deps.upstreamRepo, deps.policyRepo)
	evaluationService := service.NewEvaluationService(deps.decisionRepo)
	auditListService := service.NewAuditService(nil, deps.auditRepo, logger, cfg.Audit.Enabled, parseAuditFailureMode(cfg.Audit.FailureMode), parseAuditDetailLevel(cfg.Audit.DetailLevel))

	apidelivery.NewTenantHandler(tenantService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewPolicyHandler(policyService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewCacheHandler(cacheService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewUpstreamHandler(upstreamService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewEvaluationHandler(evaluationService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewAuditHandler(auditListService, logger).RegisterHumaRoutes(controlPlaneAPI)
}

func registerProxyRoutes(
	mux *http.ServeMux,
	deps *dependencies,
	logger *slog.Logger,
	info BuildInfo,
	bundleProvider port.TenantBundleProvider,
	registerHealth bool,
) {
	bundlePolicyRepo := bundleinfra.NewPolicyRepository(bundleProvider)
	bundleUpstreamRepo := bundleinfra.NewUpstreamRepository(bundleProvider)

	evaluator := policy.NewEvaluator()
	accessService := service.NewAccessService(
		bundlePolicyRepo,
		deps.decisionRepo,
		deps.decisionCache,
		deps.enrichmentService,
		evaluator,
		deps.ociClient,
		bundleUpstreamRepo,
		logger,
		deps.auditService,
	)

	ociHandler := ocidelivery.NewRegistryHandler(accessService, deps.ociClient, bundleUpstreamRepo, logger, deps.auditService)
	npmHandler := npmdelivery.NewRegistryHandler(accessService, deps.npmClient, bundleUpstreamRepo, logger, deps.auditService)

	if registerHealth {
		healthOptions := []service.HealthOption{
			service.WithProxyStatus("running", "proxy routes are served by this process"),
		}
		if checker, ok := bundleProvider.(service.ComponentStatusChecker); ok {
			healthOptions = append(healthOptions, service.WithBundleStatusChecker(checker))
		}

		var dbChecker service.HealthChecker
		if deps.pool != nil {
			dbChecker = &dbHealthChecker{pool: deps.pool}
		}
		var cacheChecker service.HealthChecker
		if deps.valkeyClient != nil {
			cacheChecker = &cacheHealthChecker{client: deps.valkeyClient}
		}

		healthService := service.NewHealthService(
			info.ServiceName,
			info.Version,
			info.Commit,
			info.BuildTime,
			dbChecker,
			cacheChecker,
			logger,
			healthOptions...,
		)
		healthdelivery.NewHandler(healthService).RegisterRoutes(mux)
	}

	tenantResolver := middleware.NewTenantResolver(bundleinfra.NewTenantLookup(bundleProvider))

	ociMux := http.NewServeMux()
	ociHandler.RegisterRoutes(ociMux)
	var ociWrapped http.Handler = ociMux
	ociWrapped = tenantResolver.Middleware(ociWrapped)
	ociWrapped = middleware.OCITenantFromHost()(ociWrapped)
	ociWrapped = middleware.RequestLogging(logger)(ociWrapped)
	ociWrapped = middleware.Recovery(logger)(ociWrapped)
	ociWrapped = middleware.RequestID()(ociWrapped)

	npmMux := http.NewServeMux()
	npmHandler.RegisterRoutes(npmMux)
	var npmWrapped http.Handler = npmMux
	npmWrapped = tenantResolver.Middleware(npmWrapped)
	npmWrapped = middleware.NPMTenantFromPath()(npmWrapped)
	npmWrapped = middleware.RequestLogging(logger)(npmWrapped)
	npmWrapped = middleware.Recovery(logger)(npmWrapped)
	npmWrapped = middleware.RequestID()(npmWrapped)

	mux.Handle("/v2/", ociWrapped)
	mux.Handle("/npm/", npmWrapped)
}

func openDependencies(ctx context.Context, cfg *config.Config, logger *slog.Logger, openDatabase, runMigrations bool) (*dependencies, error) {
	if openDatabase && runMigrations {
		if err := migrateDatabase(cfg); err != nil {
			return nil, err
		}
	}

	var (
		err  error
		pool *pgxpool.Pool
	)
	if openDatabase {
		pool, err = postgres.Connect(ctx, cfg.Database)
		if err != nil {
			return nil, fmt.Errorf("connecting to database: %w", err)
		}
	}
	valkeyClient, err := valkey.Connect(ctx, cfg.Valkey)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, fmt.Errorf("connecting to valkey: %w", err)
	}

	deps := &dependencies{
		pool:          pool,
		valkeyClient:  valkeyClient,
		decisionCache: valkey.NewDecisionCache(valkeyClient),
		metadataCache: valkey.NewMetadataCache(valkeyClient),
	}
	if pool != nil {
		deps.tenantRepo = postgres.NewTenantRepository(pool)
		deps.policyRepo = postgres.NewPolicyRepository(pool)
		deps.policyRevisionRepo = postgres.NewPolicyRevisionRepository(pool)
		deps.decisionRepo = postgres.NewDecisionRepository(pool)
		deps.auditRepo = postgres.NewAuditEventRepository(pool)
		deps.upstreamRepo = postgres.NewUpstreamRepository(pool)
	}

	auditRecorders := make([]port.AuditEventRecorder, 0, 2)
	if cfg.Audit.Enabled && cfg.Audit.Slog {
		auditRecorders = append(auditRecorders, auditinfra.NewSlogRecorder(logger))
	}
	if cfg.Audit.Enabled && cfg.Audit.Postgres {
		auditRecorders = append(auditRecorders, deps.auditRepo)
	}
	deps.auditService = service.NewAuditService(
		auditinfra.NewFanoutRecorder(auditRecorders...),
		deps.auditRepo,
		logger,
		cfg.Audit.Enabled,
		parseAuditFailureMode(cfg.Audit.FailureMode),
		parseAuditDetailLevel(cfg.Audit.DetailLevel),
	)

	osvEnricher := osv.NewClient(&http.Client{}, logger)
	npmEnricher := npm.NewMetadataEnricher(&http.Client{}, logger)
	deps.enricher = enrichment.NewCompositeEnricher(logger, osvEnricher, npmEnricher)
	deps.enrichmentService = service.NewEnrichmentService(deps.enricher, deps.metadataCache, logger, deps.auditService)

	baseOCIClient := upstream.NewOCIClient(newOCIHTTPClient())
	deps.ociClient = baseOCIClient
	if cfg.OCICache.Enabled {
		artifactCache, err := newOCIArtifactCache(cfg.OCICache)
		if err != nil {
			deps.close()
			return nil, fmt.Errorf("creating OCI cache: %w", err)
		}
		deps.ociClient = upstream.NewCachedOCIClient(baseOCIClient, artifactCache, logger)
	}
	deps.npmClient = upstream.NewNPMClient(&http.Client{Timeout: 30 * time.Second})

	return deps, nil
}

func (d *dependencies) close() {
	if d == nil {
		return
	}
	if d.valkeyClient != nil {
		_ = d.valkeyClient.Close()
	}
	if d.pool != nil {
		d.pool.Close()
	}
}

func migrateDatabase(cfg *config.Config) error {
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}

	migrateDSN := strings.Replace(cfg.Database.DSN, "postgres://", "pgx5://", 1)
	migrateDSN = strings.Replace(migrateDSN, "postgresql://", "pgx5://", 1)

	migrator, err := migrate.NewWithSourceInstance("iofs", source, migrateDSN)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}

	srcErr, dbErr := migrator.Close()
	if srcErr != nil {
		return fmt.Errorf("closing migration source: %w", srcErr)
	}
	if dbErr != nil {
		return fmt.Errorf("closing migration db: %w", dbErr)
	}

	return nil
}

type dbHealthChecker struct{ pool *pgxpool.Pool }

func (c *dbHealthChecker) Ping(ctx context.Context) error { return c.pool.Ping(ctx) }

type cacheHealthChecker struct{ client *redis.Client }

func (c *cacheHealthChecker) Ping(ctx context.Context) error { return c.client.Ping(ctx).Err() }

type proxyHealthChecker struct {
	url    string
	client *http.Client
}

type proxyHealthResponse struct {
	Status string `json:"status"`
	Proxy  *struct {
		Status    string    `json:"status"`
		Message   string    `json:"message"`
		Timestamp time.Time `json:"timestamp"`
	} `json:"proxy"`
	Bundle *struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"bundle"`
}

func (c *proxyHealthChecker) CheckStatus(ctx context.Context) service.ComponentStatus {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return service.ComponentStatus{
			Status:  "unreachable",
			Message: fmt.Sprintf("building proxy health request: %v", err),
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return service.ComponentStatus{
			Status:  "unreachable",
			Message: fmt.Sprintf("proxy health check failed: %v", err),
		}
	}
	defer resp.Body.Close()

	var payload proxyHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return service.ComponentStatus{
			Status:  "unreachable",
			Message: fmt.Sprintf("decoding proxy health response: %v", err),
		}
	}

	if payload.Proxy != nil {
		message := strings.TrimSpace(payload.Proxy.Message)
		if payload.Bundle != nil && strings.TrimSpace(payload.Bundle.Status) != "" {
			if message == "" {
				message = fmt.Sprintf("bundle=%s", payload.Bundle.Status)
			} else {
				message = fmt.Sprintf("%s; bundle=%s", message, payload.Bundle.Status)
			}
		}

		return service.ComponentStatus{
			Status:    payload.Proxy.Status,
			Message:   message,
			Timestamp: payload.Proxy.Timestamp,
		}
	}

	status := strings.TrimSpace(payload.Status)
	if status == "" {
		status = resp.Status
	}
	message := "proxy health endpoint reachable"
	if payload.Bundle != nil && strings.TrimSpace(payload.Bundle.Status) != "" {
		message = fmt.Sprintf("%s; bundle=%s", message, payload.Bundle.Status)
	}

	return service.ComponentStatus{
		Status:  status,
		Message: message,
	}
}

type server struct {
	name     string
	start    func() error
	shutdown func(context.Context) error
}

func serve(ctx context.Context, logger *slog.Logger, servers ...server) error {
	runCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, len(servers))
	for i := range servers {
		srv := servers[i]
		go func() {
			err := srv.start()
			if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, grpc.ErrServerStopped) {
				errCh <- nil
				return
			}
			errCh <- fmt.Errorf("%s: %w", srv.name, err)
		}()
	}

	var runErr error
	select {
	case <-runCtx.Done():
		logger.Info("received shutdown signal")
	case err := <-errCh:
		if err != nil {
			runErr = err
			logger.Error("server exited", "error", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	shutdownErrCh := make(chan error, len(servers))
	for i := range servers {
		srv := servers[i]
		if srv.shutdown == nil {
			continue
		}
		wg.Go(func() {
			if err := srv.shutdown(shutdownCtx); err != nil {
				shutdownErrCh <- err
			}
		})
	}
	wg.Wait()
	close(shutdownErrCh)

	for err := range shutdownErrCh {
		if err != nil && runErr == nil {
			runErr = fmt.Errorf("graceful shutdown: %w", err)
		}
	}

	return runErr
}

func newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}
}

func newOCIHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
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

func parseAuditFailureMode(value string) domain.AuditFailureMode {
	if strings.EqualFold(strings.TrimSpace(value), string(domain.AuditFailureModeFailOpen)) {
		return domain.AuditFailureModeFailOpen
	}
	return domain.AuditFailureModeFailClosed
}

func parseAuditDetailLevel(value string) domain.AuditDetailLevel {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(domain.AuditDetailLevelMinimal):
		return domain.AuditDetailLevelMinimal
	case string(domain.AuditDetailLevelFull):
		return domain.AuditDetailLevelFull
	default:
		return domain.AuditDetailLevelSummary
	}
}

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}
