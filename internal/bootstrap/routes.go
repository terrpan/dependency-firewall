package bootstrap

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	apidelivery "github.com/danielterry/dependency-firewall/internal/delivery/api"
	healthdelivery "github.com/danielterry/dependency-firewall/internal/delivery/health"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
	npmdelivery "github.com/danielterry/dependency-firewall/internal/delivery/npm"
	ocidelivery "github.com/danielterry/dependency-firewall/internal/delivery/oci"
	bundleinfra "github.com/danielterry/dependency-firewall/internal/infra/bundle"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

func registerControlPlaneRoutes(
	mux *http.ServeMux,
	deps *dependencies,
	cfg *config.Config,
	logger *slog.Logger,
	info BuildInfo,
) error {
	controlPlaneAPI := apidelivery.NewControlPlaneAPI(mux, info.Version)

	healthOptions := []service.HealthOption{}
	if cfg.Runtime.Mode == config.RuntimeModeControlPlane {
		if proxyURL := strings.TrimSpace(cfg.Health.ProxyURL); proxyURL != "" {
			healthOptions = append(healthOptions, service.WithProxyStatusChecker(&proxyHealthChecker{
				url:    proxyURL,
				client: telemetry.WrapHTTPClient(&http.Client{Timeout: 3 * time.Second}),
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

	return nil
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
