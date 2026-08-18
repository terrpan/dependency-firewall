package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/bundlegrpc"
	"github.com/danielterry/dependency-firewall/internal/delivery/ingestgrpc"
	bundleinfra "github.com/danielterry/dependency-firewall/internal/infra/bundle"
	"github.com/danielterry/dependency-firewall/internal/infra/controlplanegrpc"
	ingestinfra "github.com/danielterry/dependency-firewall/internal/infra/ingest"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

// RunControlPlane starts the control-plane HTTP API and bundle gRPC service.
func RunControlPlane(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	return runWithRuntimeDependencies(
		ctx,
		cfg,
		logger,
		info,
		true,
		true,
		func(logger *slog.Logger, deps *dependencies) error {
			installRuntimeServices(cfg, logger, deps, deps.auditRepo, deps.auditRepo)

			controlPlaneMux := http.NewServeMux()
			if err := registerControlPlaneRoutes(controlPlaneMux, deps, cfg, logger, info); err != nil {
				return err
			}

			httpServer := newHTTPServer(cfg, controlPlaneMux)

			controlPlaneGRPCOptions, err := controlPlaneGRPCServerOptions(cfg, logger, deps.auditService)
			if err != nil {
				return err
			}
			if cfg.Bundle.TLS.Mode == "mtls" {
				if deps.bundleUpstreamRepo == nil {
					return fmt.Errorf("bundle upstream repository is required in mTLS mode")
				}
				if deps.authSecretRewrapper == nil {
					return fmt.Errorf("upstream auth secret rewrapper is required in mTLS mode")
				}
			}
			grpcServer := grpc.NewServer(controlPlaneGRPCOptions...)
			bundleService, err := newLocalBundleService(deps, cfg.Bundle.TLS.Mode == "mtls")
			if err != nil {
				return err
			}
			bundleServer, err := bundlegrpc.NewServer(bundleService, deps.authSecretRewrapper)
			if err != nil {
				return err
			}
			bundleServer.Register(grpcServer)
			graphJobNotifier := service.NewDependencyGraphJobNotifier()
			ingestgrpc.NewServer(service.NewProxyIngestService(deps.decisionRepo, deps.auditRepo, deps.dependencyGraphQueue, graphJobNotifier)).
				Register(grpcServer)

			listener, err := net.Listen("tcp", cfg.Bundle.ListenAddr)
			if err != nil {
				return fmt.Errorf("listening for bundle grpc: %w", err)
			}
			defer listener.Close()

			logger.Info("starting control plane",
				"http_addr", httpServer.Addr,
				"bundle_addr", cfg.Bundle.ListenAddr,
			)
			if cfg.Bundle.TLS.Mode != "mtls" && cfg.Bundle.TLS.AllowInsecureControlPlane {
				logger.Warn("control plane gRPC is running without mTLS",
					"bundle_addr", cfg.Bundle.ListenAddr,
					"runtime_mode", cfg.Runtime.Mode,
					"bundle_tls_mode", cfg.Bundle.TLS.Mode,
					"override", "bundle.tls.allow_insecure_control_plane",
				)
			}

			return serve(ctx, logger,
				httpServerRunner("control-plane-http", httpServer),
				grpcServerRunner("control-plane-grpc", grpcServer, listener),
				optionalDependencyGraphWorkerRunner(ctx, cfg, logger, deps.dependencyGraphRepo, graphJobNotifier),
			)
		},
	)
}

// RunProxy starts the proxy HTTP service with a remote bundle client.
func RunProxy(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	return runWithRuntimeDependencies(
		ctx,
		cfg,
		logger,
		info,
		false,
		false,
		func(logger *slog.Logger, deps *dependencies) error {
			grpcClient, err := bundleinfra.NewGRPCClient(ctx, cfg.Bundle.ControlPlaneAddr, cfg.Bundle.TLS)
			if err != nil {
				return err
			}
			defer grpcClient.Close()

			ingestClient, err := ingestinfra.NewGRPCClient(ctx, cfg.Bundle.ControlPlaneAddr, cfg.Bundle.TLS)
			if err != nil {
				return err
			}
			defer ingestClient.Close()

			deps.decisionRepo = ingestinfra.NewDecisionRepository(ingestClient)
			deps.dependencyGraphQueue = ingestinfra.NewDependencyGraphQueue(ingestClient)
			deps.dependencyGraphContexts = ingestClient
			installRuntimeServices(cfg, logger, deps, nil, ingestinfra.NewAuditEventRecorder(ingestClient))

			bundleProvider := service.NewCachedBundleProvider(grpcClient, cfg.Bundle.RefreshInterval, logger)
			return runProxyHTTP(ctx, cfg, logger, info, deps, bundleProvider)
		},
	)
}

// RunAllInOne starts the combined local runtime with control-plane HTTP and proxy HTTP.
func RunAllInOne(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	return runWithRuntimeDependencies(
		ctx,
		cfg,
		logger,
		info,
		true,
		true,
		func(logger *slog.Logger, deps *dependencies) error {
			installRuntimeServices(cfg, logger, deps, deps.auditRepo, deps.auditRepo)

			bundleService, err := newLocalBundleService(deps, true)
			if err != nil {
				return err
			}

			localBundles := service.NewCachedBundleProvider(
				bundleService,
				cfg.Bundle.RefreshInterval,
				logger,
			)
			graphJobNotifier := service.NewDependencyGraphJobNotifier()
			localIngest := service.NewProxyIngestService(
				deps.decisionRepo,
				deps.auditRepo,
				deps.dependencyGraphQueue,
				graphJobNotifier,
			)
			proxyDeps := *deps
			proxyDeps.decisionRepo = ingestinfra.NewLocalDecisionRepository(localIngest)
			proxyDeps.dependencyGraphQueue = ingestinfra.NewLocalDependencyGraphQueue(localIngest)
			installRuntimeServices(cfg, logger, &proxyDeps, nil, ingestinfra.NewLocalAuditEventRecorder(localIngest))

			mux := http.NewServeMux()
			if err := registerControlPlaneRoutes(mux, deps, cfg, logger, BuildInfo{
				ServiceName: info.ServiceName,
				Version:     info.Version,
				Commit:      info.Commit,
				BuildTime:   info.BuildTime,
			}); err != nil {
				return err
			}
			registerProxyRoutes(mux, &proxyDeps, logger, info, localBundles, false)

			httpServer := newHTTPServer(cfg, mux)
			logger.Info("starting all-in-one firewall",
				"http_addr", httpServer.Addr,
			)

			return serve(ctx, logger,
				httpServerRunner("firewall-http", httpServer),
				optionalDependencyGraphWorkerRunner(ctx, cfg, logger, deps.dependencyGraphRepo, graphJobNotifier),
			)
		},
	)
}

// RunDependencyGraphWorker starts the isolated npm dependency graph resolver process.
func RunDependencyGraphWorker(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	telemetryProvider, runtimeLogger, err := startTelemetry(ctx, cfg, logger, info)
	if err != nil {
		return err
	}
	defer shutdownTelemetry(telemetryProvider)

	ingestClient, err := ingestinfra.NewGRPCClient(ctx, cfg.Bundle.ControlPlaneAddr, cfg.Bundle.TLS)
	if err != nil {
		return err
	}
	defer ingestClient.Close()

	runtimeLogger.Info("starting dependency graph worker",
		"control_plane_addr", cfg.Bundle.ControlPlaneAddr,
		"tenant_id", cfg.DependencyGraph.TenantID,
	)
	return serve(ctx, runtimeLogger, dependencyGraphWorkerRunner(ctx, cfg, runtimeLogger, ingestClient, ingestClient))
}

func newLocalBundleService(deps *dependencies, includeUpstreamAuth bool) (*service.BundleService, error) {
	return service.NewBundleService(
		deps.tenantRepo,
		deps.policyRepo,
		deps.upstreamRepo,
		service.WithBundleUpstreamAuth(includeUpstreamAuth),
		service.WithBundleUpstreamRepository(deps.bundleUpstreamRepo),
	)
}

func runWithRuntimeDependencies(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	info BuildInfo,
	openDatabase bool,
	runMigrations bool,
	run func(logger *slog.Logger, deps *dependencies) error,
) error {
	telemetryProvider, runtimeLogger, err := startTelemetry(ctx, cfg, logger, info)
	if err != nil {
		return err
	}
	defer shutdownTelemetry(telemetryProvider)

	deps, err := openDependencies(ctx, cfg, runtimeLogger, openDatabase, runMigrations)
	if err != nil {
		return err
	}
	defer deps.close()

	return run(runtimeLogger, deps)
}

func controlPlaneGRPCServerOptions(
	cfg *config.Config,
	logger *slog.Logger,
	auditService *service.AuditService,
) ([]grpc.ServerOption, error) {
	options, err := controlplanegrpc.ServerOptions(cfg.Bundle.TLS)
	if err != nil {
		return nil, err
	}
	if cfg.Bundle.TLS.Mode == "mtls" {
		options = append(options, grpc.UnaryInterceptor(controlplanegrpc.TenantAuthorizationInterceptor(
			cfg.Bundle.TLS.AuthorizedClients,
			controlPlaneTenantIDFromRequest,
			controlplanegrpc.WithTenantAuthorizationLogger(logger),
			controlplanegrpc.WithTenantAuthorizationDeniedRecorder(
				controlPlaneAuthorizationDeniedRecorder(auditService),
			),
		)))
		options = append(options, grpc.StreamInterceptor(controlplanegrpc.TenantAuthorizationStreamInterceptor(
			cfg.Bundle.TLS.AuthorizedClients,
			controlPlaneTenantIDFromRequest,
			controlplanegrpc.WithTenantAuthorizationLogger(logger),
			controlplanegrpc.WithTenantAuthorizationDeniedRecorder(
				controlPlaneAuthorizationDeniedRecorder(auditService),
			),
		)))
	}
	return append(options, telemetry.ServerOptions()...), nil
}

func controlPlaneAuthorizationDeniedRecorder(
	auditService *service.AuditService,
) controlplanegrpc.TenantAuthorizationDeniedRecorder {
	return func(ctx context.Context, event controlplanegrpc.TenantAuthorizationDeniedEvent) error {
		if auditService == nil || !auditService.Enabled() || event.TenantID == "" {
			return nil
		}
		return auditService.Record(ctx, domain.AuditEvent{
			TenantID:   event.TenantID,
			EventType:  domain.AuditEventRequestDenied,
			Source:     "control-plane/grpc-authz",
			Outcome:    domain.DecisionDeny,
			Message:    "control-plane grpc request denied",
			CreatedAt:  time.Now().UTC(),
			EntityType: "control_plane_grpc_request",
			Payload: map[string]any{
				"client_identities":  event.ClientIdentities,
				"grpc_method":        event.FullMethod,
				"permission_message": event.PermissionMessage,
				"reason":             event.Reason,
			},
		})
	}
}

func controlPlaneTenantIDFromRequest(req any) string {
	if tenantID := bundlegrpc.TenantIDFromRequest(req); tenantID != "" {
		return tenantID
	}
	return ingestgrpc.TenantIDFromRequest(req)
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

	return serve(ctx, logger, httpServerRunner("proxy-http", httpServer))
}

func optionalDependencyGraphWorkerRunner(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	resolver port.DependencyGraphResolver,
	watcher port.DependencyGraphJobWatcher,
) server {
	if !cfg.DependencyGraph.RunInProcess {
		return server{name: "dependency-graph-worker-disabled", start: func() error { <-ctx.Done(); return nil }}
	}
	return dependencyGraphWorkerRunner(ctx, cfg, logger, resolver, watcher)
}

func dependencyGraphWorkerRunner(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	resolver port.DependencyGraphResolver,
	watcher port.DependencyGraphJobWatcher,
) server {
	worker := service.NewDependencyGraphWorker(resolver, watcher, service.DependencyGraphWorkerConfig{
		Enabled:      cfg.DependencyGraph.Enabled,
		TenantID:     cfg.DependencyGraph.TenantID,
		PollInterval: cfg.DependencyGraph.PollInterval,
		Timeout:      cfg.DependencyGraph.Timeout,
		Concurrency:  cfg.DependencyGraph.Concurrency,
		RetryDelay:   cfg.DependencyGraph.RetryDelay,
	}, logger)
	return server{
		name: "dependency-graph-worker",
		start: func() error {
			return worker.Run(ctx)
		},
		shutdown: nil,
	}
}

func httpServerRunner(name string, httpServer *http.Server) server {
	return server{
		name: name,
		start: func() error {
			return httpServer.ListenAndServe()
		},
		shutdown: func(ctx context.Context) error {
			return httpServer.Shutdown(ctx)
		},
	}
}

func grpcServerRunner(name string, grpcServer *grpc.Server, listener net.Listener) server {
	return server{
		name: name,
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
	}
}
