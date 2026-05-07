// modes.go contains the concrete control-plane, proxy, and all-in-one runtime modes.
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
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/bundlegrpc"
	"github.com/danielterry/dependency-firewall/internal/delivery/ingestgrpc"
	auditinfra "github.com/danielterry/dependency-firewall/internal/infra/audit"
	bundleinfra "github.com/danielterry/dependency-firewall/internal/infra/bundle"
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

	grpcServer := grpc.NewServer(append([]grpc.ServerOption{
		grpc.ForceServerCodec(jsonCodec{}),
	}, telemetry.ServerOptions()...)...)
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
