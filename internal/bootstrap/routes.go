package bootstrap

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

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
			healthOptions = append(
				healthOptions,
				service.WithProxyStatus("separate", "proxy runs as a separate service in control-plane mode"),
			)
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
	policyService := service.NewPolicyService(
		deps.policyRepo,
		deps.policyRevisionRepo,
		deps.decisionCache,
		deps.upstreamRepo,
	)
	cacheService := service.NewCacheService(deps.decisionCache, deps.metadataCache)
	upstreamService := service.NewUpstreamService(
		deps.upstreamRepo,
		deps.policyRepo,
		service.WithAuthenticatedUpstreams(
			cfg.Runtime.Mode != config.RuntimeModeControlPlane || cfg.Bundle.TLS.Mode == "mtls",
		),
	)
	evaluationService := service.NewEvaluationService(deps.decisionRepo)
	auditListService := service.NewAuditService(
		nil,
		deps.auditRepo,
		logger,
		cfg.Audit.Enabled,
		parseAuditFailureMode(cfg.Audit.FailureMode),
		parseAuditDetailLevel(cfg.Audit.DetailLevel),
	)

	apidelivery.NewTenantHandler(tenantService, logger).RegisterHumaRoutes(controlPlaneAPI)
	if err := registerProxyEnrollmentRoutes(controlPlaneAPI, deps, cfg, logger); err != nil {
		return err
	}
	apidelivery.NewPolicyHandler(policyService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewCacheHandler(cacheService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewUpstreamHandler(upstreamService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewEvaluationHandler(evaluationService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewAuditHandler(auditListService, logger).RegisterHumaRoutes(controlPlaneAPI)
	if deps.dependencyGraphRepo != nil {
		apidelivery.NewDependencyGraphHandler(deps.dependencyGraphRepo, logger).RegisterHumaRoutes(controlPlaneAPI)
	}

	return nil
}

func registerProxyEnrollmentRoutes(api huma.API, deps *dependencies, cfg *config.Config, logger *slog.Logger) error {
	if !cfg.Enrollment.Enabled {
		return nil
	}
	enrollmentService, err := service.NewProxyEnrollmentService(
		deps.proxyEnrollmentRepo, deps.proxyEnrollmentRepo,
		service.DenyAllTenantApprovalAuthorizer{}, deps.workloadIssuer, deps.enrollmentHMACKey,
		service.ProxyEnrollmentSettings{
			VerificationURI: cfg.Enrollment.VerificationURI, PublicGRPCAddress: cfg.Enrollment.PublicGRPCAddress,
			GRPCServerName: cfg.Enrollment.GRPCServerName, Validity: cfg.Enrollment.Validity,
			PollInterval: cfg.Enrollment.PollInterval,
		},
	)
	if err != nil {
		return err
	}
	apidelivery.NewProxyEnrollmentHandler(
		enrollmentService,
		apidelivery.AnonymousPrincipalProvider{},
		logger,
		apidelivery.ProxyEnrollmentHandlerSettings{
			PublicAPIURL:      cfg.Enrollment.PublicAPIURL,
			PublicGRPCAddress: cfg.Enrollment.PublicGRPCAddress,
			GRPCServerName:    cfg.Enrollment.GRPCServerName,
		},
	).RegisterHumaRoutes(api)
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
	accessService := newProxyAccessService(deps, logger, bundlePolicyRepo, bundleUpstreamRepo)

	if registerHealth {
		registerProxyHealthRoutes(mux, deps, logger, info, bundleProvider)
	}

	tenantResolver := middleware.NewTenantResolver(bundleinfra.NewTenantLookup(bundleProvider))
	mux.Handle("/v2/", newOCIProxyHandler(accessService, deps, bundleUpstreamRepo, logger, tenantResolver))
	mux.Handle("/npm/", newNPMProxyHandler(accessService, deps, bundleUpstreamRepo, logger, tenantResolver))
}

func newProxyAccessService(
	deps *dependencies,
	logger *slog.Logger,
	bundlePolicyRepo port.PolicyRepository,
	bundleUpstreamRepo port.UpstreamRepository,
) *service.AccessService {
	dependencyContextService := service.NewDependencyContextService(
		deps.dependencyContextCache,
		deps.dependencyGraphContexts,
		deps.dependencyGraphQueue,
		logger,
	)
	return service.NewAccessService(
		bundlePolicyRepo,
		deps.decisionRepo,
		deps.decisionCache,
		deps.enrichmentService,
		policy.NewEvaluator(),
		deps.ociClient,
		bundleUpstreamRepo,
		logger,
		deps.auditService,
		service.WithDependencyContextService(dependencyContextService),
	)
}

func registerProxyHealthRoutes(
	mux *http.ServeMux,
	deps *dependencies,
	logger *slog.Logger,
	info BuildInfo,
	bundleProvider port.TenantBundleProvider,
) {
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

func newOCIProxyHandler(
	accessService *service.AccessService,
	deps *dependencies,
	bundleUpstreamRepo port.UpstreamRepository,
	logger *slog.Logger,
	tenantResolver *middleware.TenantResolver,
) http.Handler {
	ociHandler := ocidelivery.NewRegistryHandler(
		accessService,
		deps.ociClient,
		bundleUpstreamRepo,
		logger,
		deps.auditService,
	)
	ociMux := http.NewServeMux()
	ociHandler.RegisterRoutes(ociMux)
	var wrapped http.Handler = ociMux
	wrapped = enforceBoundProxyTenant(deps.boundTenantID, wrapped)
	wrapped = tenantResolver.Middleware(wrapped)
	wrapped = middleware.OCITenantFromHost()(wrapped)
	wrapped = middleware.RequestLogging(logger)(wrapped)
	wrapped = middleware.Recovery(logger)(wrapped)
	return middleware.RequestID()(wrapped)
}

func newNPMProxyHandler(
	accessService *service.AccessService,
	deps *dependencies,
	bundleUpstreamRepo port.UpstreamRepository,
	logger *slog.Logger,
	tenantResolver *middleware.TenantResolver,
) http.Handler {
	npmHandler := npmdelivery.NewRegistryHandler(
		accessService,
		deps.npmClient,
		bundleUpstreamRepo,
		logger,
		deps.auditService,
		newNPMInstallSnapshotService(deps, logger),
	)
	npmMux := http.NewServeMux()
	npmHandler.RegisterRoutes(npmMux)
	var wrapped http.Handler = npmMux
	wrapped = enforceBoundProxyTenant(deps.boundTenantID, wrapped)
	wrapped = tenantResolver.Middleware(wrapped)
	wrapped = middleware.NPMTenantFromPath()(wrapped)
	wrapped = middleware.RequestLogging(logger)(wrapped)
	wrapped = middleware.Recovery(logger)(wrapped)
	return middleware.RequestID()(wrapped)
}

func enforceBoundProxyTenant(boundTenantID string, next http.Handler) http.Handler {
	boundTenantID = strings.TrimSpace(boundTenantID)
	if boundTenantID == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := middleware.TenantFromContext(r.Context())
		if !ok || tenant.ID != boundTenantID {
			http.Error(w, "proxy enrollment is not authorized for this tenant", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newNPMInstallSnapshotService(
	deps *dependencies,
	logger *slog.Logger,
) *service.NPMInstallSnapshotService {
	manifests, ok := deps.npmClient.(port.NPMManifestDependencyLister)
	if !ok || deps.dependencyGraphQueue == nil {
		return nil
	}
	return service.NewNPMInstallSnapshotService(manifests, deps.dependencyGraphQueue, logger)
}
