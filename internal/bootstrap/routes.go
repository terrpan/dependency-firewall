package bootstrap

import (
	"fmt"
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
	clerkinfra "github.com/danielterry/dependency-firewall/internal/infra/clerk"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

func registerControlPlaneRoutes(
	mux *http.ServeMux,
	deps *dependencies,
	cfg *config.Config,
	logger *slog.Logger,
	info BuildInfo,
) error {
	if cfg.Auth.Mode == "" || cfg.Auth.Mode == "disabled" {
		logger.Error(
			"SECURITY: human control-plane authentication is disabled; compatibility mode must not be exposed publicly",
		)
	}
	controlPlaneAPI := apidelivery.NewControlPlaneAPI(mux, info.Version)
	apidelivery.NewHealthHandler(newControlPlaneHealthService(deps, cfg, logger, info), logger).
		RegisterHumaRoutes(controlPlaneAPI)

	services := newControlPlaneServices(deps, cfg, logger)

	sessionBootstrapService, tenantMembershipVerifier, err := registerControlPlaneAuth(
		controlPlaneAPI, cfg, deps, services.authorization, logger,
	)
	if err != nil {
		return err
	}
	hierarchyService := service.NewHierarchyService(
		deps.organizationRepo,
		deps.organizationMembers,
		deps.teamRepo,
		deps.teamMembers,
		deps.principalRepo,
		services.authorization,
		tenantMembershipVerifier,
	)

	registerControlPlaneHandlers(controlPlaneAPI, deps, services, hierarchyService, sessionBootstrapService, logger)
	return nil
}

// controlPlaneServices bundles the control-plane business-logic services so
// registerControlPlaneRoutes can wire them into HTTP handlers without a long
// list of local variables.
type controlPlaneServices struct {
	tenant         *service.TenantService
	session        *service.SessionService
	policy         *service.PolicyService
	cache          *service.CacheService
	upstream       *service.UpstreamService
	evaluation     *service.EvaluationService
	auditList      *service.AuditService
	authorization  *service.AuthorizationService
	scopedPolicy   *service.ScopedPolicyService
	scopedUpstream *service.ScopedUpstreamService
}

func newControlPlaneServices(deps *dependencies, cfg *config.Config, logger *slog.Logger) *controlPlaneServices {
	authorizationService := service.NewAuthorizationService(
		deps.organizationRepo,
		deps.organizationMembers,
		deps.teamRepo,
		deps.teamMembers,
	)
	policyService := service.NewPolicyService(
		deps.policyRepo,
		deps.policyRevisionRepo,
		deps.decisionCache,
		deps.upstreamRepo,
	)
	upstreamService := service.NewUpstreamService(
		deps.upstreamRepo,
		deps.policyRepo,
		service.WithAuthenticatedUpstreams(
			cfg.Runtime.Mode != config.RuntimeModeControlPlane || cfg.Bundle.TLS.Mode == "mtls",
		),
	)
	return &controlPlaneServices{
		tenant:     service.NewTenantService(deps.tenantRepo),
		session:    service.NewSessionService(deps.tenantRepo, deps.organizationRepo, deps.organizationMembers),
		policy:     policyService,
		cache:      service.NewCacheService(deps.decisionCache, deps.metadataCache),
		upstream:   upstreamService,
		evaluation: service.NewEvaluationService(deps.decisionRepo),
		auditList: service.NewAuditService(
			nil,
			deps.auditRepo,
			logger,
			cfg.Audit.Enabled,
			parseAuditFailureMode(cfg.Audit.FailureMode),
			parseAuditDetailLevel(cfg.Audit.DetailLevel),
		),
		authorization: authorizationService,
		scopedPolicy:  service.NewScopedPolicyService(policyService, deps.scopedPolicyRepo, authorizationService),
		scopedUpstream: service.NewScopedUpstreamService(
			upstreamService,
			deps.scopedUpstreamRepo,
			authorizationService,
		),
	}
}

func newControlPlaneHealthService(
	deps *dependencies,
	cfg *config.Config,
	logger *slog.Logger,
	info BuildInfo,
) *service.HealthService {
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
	return service.NewHealthService(
		info.ServiceName,
		info.Version,
		info.Commit,
		info.BuildTime,
		&dbHealthChecker{pool: deps.pool},
		&cacheHealthChecker{client: deps.valkeyClient},
		logger,
		healthOptions...,
	)
}

// registerControlPlaneAuth wires the human-authentication middleware onto the
// control-plane API when Clerk auth is enabled. It returns the session
// bootstrap service and tenant membership verifier the caller needs to build
// the session and hierarchy services; both are nil when auth is disabled.
func registerControlPlaneAuth(
	controlPlaneAPI huma.API,
	cfg *config.Config,
	deps *dependencies,
	authorizationService *service.AuthorizationService,
	logger *slog.Logger,
) (*service.SessionBootstrapService, service.TenantMembershipVerifier, error) {
	if cfg.Auth.Mode != "clerk" {
		return nil, nil, nil
	}
	authenticator, err := clerkinfra.NewAuthenticator(cfg.Auth.Clerk)
	if err != nil {
		return nil, nil, fmt.Errorf("registering control-plane routes: %w", err)
	}
	directory := clerkinfra.NewDirectory(
		cfg.Auth.Clerk.SecretKey,
		telemetry.WrapHTTPClient(newOutboundHTTPClient(10*time.Second)),
	)
	sessionBootstrapService := service.NewSessionBootstrapService(directory, deps.sessionBootstrap)
	identityService := service.NewIdentityService(deps.tenantIdentityLinks, deps.principalRepo)
	controlPlaneAPI.UseMiddleware(middleware.HumanAuthentication(
		controlPlaneAPI, authenticator, identityService, authorizationService, directory,
		func(operationID string) (middleware.HumanOperationPolicy, bool) {
			policy, ok := apidelivery.ControlPlaneOperationPolicy(operationID)
			return middleware.HumanOperationPolicy{
				AuthenticationRequired: policy.AuthenticationRequired,
				Permission:             policy.Permission,
				Bootstrap:              policy.Bootstrap,
				FreshMembership:        policy.FreshMembership,
				ScopedAuthorization:    policy.ScopedAuthorization,
			}, ok
		},
	))
	return sessionBootstrapService, directory, nil
}

func registerControlPlaneHandlers(
	controlPlaneAPI huma.API,
	deps *dependencies,
	services *controlPlaneServices,
	hierarchyService *service.HierarchyService,
	sessionBootstrapService *service.SessionBootstrapService,
	logger *slog.Logger,
) {
	apidelivery.NewTenantHandler(services.tenant, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewSessionHandler(services.session, logger, sessionBootstrapService).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewHierarchyHandler(hierarchyService, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewPolicyHandler(services.policy, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewCacheHandler(services.cache, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewUpstreamHandler(services.upstream, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewScopedResourceHandler(services.scopedPolicy, services.scopedUpstream, logger).
		RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewEvaluationHandler(services.evaluation, logger).RegisterHumaRoutes(controlPlaneAPI)
	apidelivery.NewAuditHandler(services.auditList, logger).RegisterHumaRoutes(controlPlaneAPI)
	if deps.dependencyGraphRepo != nil {
		apidelivery.NewDependencyGraphHandler(deps.dependencyGraphRepo, logger).RegisterHumaRoutes(controlPlaneAPI)
	}
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
	credentialAuth := middleware.NewDataPlaneCredentialMiddleware(bundleProvider)
	mux.Handle(
		"/v2/",
		newOCIProxyHandler(accessService, deps, bundleUpstreamRepo, logger, tenantResolver, credentialAuth),
	)
	mux.Handle(
		"/npm/",
		newNPMProxyHandler(accessService, deps, bundleUpstreamRepo, logger, tenantResolver, credentialAuth),
	)
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
	credentialAuth *middleware.DataPlaneCredentialMiddleware,
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
	wrapped = tenantResolver.Middleware(wrapped)
	wrapped = credentialAuth.Middleware(wrapped)
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
	credentialAuth *middleware.DataPlaneCredentialMiddleware,
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
	wrapped = tenantResolver.Middleware(wrapped)
	wrapped = credentialAuth.Middleware(wrapped)
	wrapped = middleware.NPMTenantFromPath()(wrapped)
	wrapped = middleware.RequestLogging(logger)(wrapped)
	wrapped = middleware.Recovery(logger)(wrapped)
	return middleware.RequestID()(wrapped)
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
