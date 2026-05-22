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
	auditinfra "github.com/danielterry/dependency-firewall/internal/infra/audit"
	bundleinfra "github.com/danielterry/dependency-firewall/internal/infra/bundle"
	"github.com/danielterry/dependency-firewall/internal/infra/controlplanegrpc"
	ingestinfra "github.com/danielterry/dependency-firewall/internal/infra/ingest"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

// RunControlPlane starts the control-plane HTTP API and bundle gRPC service.
func RunControlPlane(ctx context.Context, cfg *config.Config, logger *slog.Logger, info BuildInfo) error {
	telemetryProvider, logger, err := startTelemetry(ctx, cfg, logger, info)
	if err != nil {
		return err
	}
	defer shutdownTelemetry(telemetryProvider)

	deps, err := openDependencies(ctx, cfg, logger, true, true)
	if err != nil {
		return err
	}
	defer deps.close()

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
	bundleService, err := service.NewBundleService(
		deps.tenantRepo,
		deps.policyRepo,
		deps.upstreamRepo,
		service.WithBundleUpstreamAuth(cfg.Bundle.TLS.Mode == "mtls"),
		service.WithBundleUpstreamRepository(deps.bundleUpstreamRepo),
	)
	if err != nil {
		return err
	}
	bundleServer, err := bundlegrpc.NewServer(bundleService, deps.authSecretRewrapper)
	if err != nil {
		return err
	}
	bundleServer.Register(grpcServer)
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
	if cfg.Bundle.TLS.Mode != "mtls" && cfg.Bundle.TLS.AllowInsecureControlPlane {
		logger.Warn("control plane gRPC is running without mTLS",
			"bundle_addr", cfg.Bundle.ListenAddr,
			"runtime_mode", cfg.Runtime.Mode,
			"bundle_tls_mode", cfg.Bundle.TLS.Mode,
			"override", "bundle.tls.allow_insecure_control_plane",
		)
	}

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
	telemetryProvider, logger, err := startTelemetry(ctx, cfg, logger, info)
	if err != nil {
		return err
	}
	defer shutdownTelemetry(telemetryProvider)

	deps, err := openDependencies(ctx, cfg, logger, false, false)
	if err != nil {
		return err
	}
	defer deps.close()

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
	telemetryProvider, logger, err := startTelemetry(ctx, cfg, logger, info)
	if err != nil {
		return err
	}
	defer shutdownTelemetry(telemetryProvider)

	deps, err := openDependencies(ctx, cfg, logger, true, true)
	if err != nil {
		return err
	}
	defer deps.close()

	bundleService, err := service.NewBundleService(
		deps.tenantRepo,
		deps.policyRepo,
		deps.upstreamRepo,
		service.WithBundleUpstreamAuth(true),
		service.WithBundleUpstreamRepository(deps.bundleUpstreamRepo),
	)
	if err != nil {
		return err
	}

	localBundles := service.NewCachedBundleProvider(
		bundleService,
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

func controlPlaneGRPCServerOptions(cfg *config.Config, logger *slog.Logger, auditService *service.AuditService) ([]grpc.ServerOption, error) {
	options, err := controlplanegrpc.ServerOptions(cfg.Bundle.TLS)
	if err != nil {
		return nil, err
	}
	if cfg.Bundle.TLS.Mode == "mtls" {
		options = append(options, grpc.UnaryInterceptor(controlplanegrpc.TenantAuthorizationInterceptor(
			cfg.Bundle.TLS.AuthorizedClients,
			controlPlaneTenantIDFromRequest,
			controlplanegrpc.WithTenantAuthorizationLogger(logger),
			controlplanegrpc.WithTenantAuthorizationDeniedRecorder(controlPlaneAuthorizationDeniedRecorder(auditService)),
		)))
	}
	return append(options, telemetry.ServerOptions()...), nil
}

func controlPlaneAuthorizationDeniedRecorder(auditService *service.AuditService) controlplanegrpc.TenantAuthorizationDeniedRecorder {
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
