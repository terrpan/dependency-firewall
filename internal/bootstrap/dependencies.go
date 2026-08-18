package bootstrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	auditinfra "github.com/danielterry/dependency-firewall/internal/infra/audit"
	"github.com/danielterry/dependency-firewall/internal/infra/enrichment"
	"github.com/danielterry/dependency-firewall/internal/infra/npm"
	"github.com/danielterry/dependency-firewall/internal/infra/osv"
	"github.com/danielterry/dependency-firewall/internal/infra/postgres"
	"github.com/danielterry/dependency-firewall/internal/infra/scorecard"
	"github.com/danielterry/dependency-firewall/internal/infra/secrets"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
	"github.com/danielterry/dependency-firewall/internal/infra/upstream"
	valkeyinfra "github.com/danielterry/dependency-firewall/internal/infra/valkey"
)

type dependencies struct {
	pool         *pgxpool.Pool
	valkeyClient valkeygo.Client

	tenantRepo           port.TenantRepository
	policyRepo           port.PolicyRepository
	policyRevisionRepo   port.PolicyRevisionRepository
	decisionRepo         port.DecisionRepository
	dependencyGraphRepo  port.DependencyGraphRepository
	dependencyGraphQueue port.DependencyGraphQueue
	// dependencyGraphContexts loads graph context summaries; Postgres-backed in
	// DB-owning runtimes, gRPC-backed in split-mode proxies.
	dependencyGraphContexts port.DependencyGraphContextLookup
	auditRepo               *postgres.AuditEventRepository
	upstreamRepo            port.UpstreamRepository
	bundleUpstreamRepo      port.BundleUpstreamRepository
	authSecretRewrapper     port.UpstreamAuthSecretRewrapper

	decisionCache          port.DecisionCache
	metadataCache          port.MetadataCache
	dependencyContextCache port.DependencyContextCache
	enricher               port.Enricher

	auditService      *service.AuditService
	enrichmentService *service.EnrichmentService
	ociClient         port.UpstreamClient
	npmClient         port.UpstreamClient
}

func openDependencies(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	openDatabase, runMigrations bool,
) (*dependencies, error) {
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
		pool, err = postgres.Connect(ctx, cfg.Database, cfg.Telemetry.SQLTracing)
		if err != nil {
			return nil, fmt.Errorf("connecting to database: %w", err)
		}
	}
	valkeyClient, err := valkeyinfra.Connect(ctx, cfg.Valkey)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, fmt.Errorf("connecting to valkey: %w", err)
	}

	deps := &dependencies{
		pool:                   pool,
		valkeyClient:           valkeyClient,
		decisionCache:          valkeyinfra.NewDecisionCache(valkeyClient),
		metadataCache:          valkeyinfra.NewMetadataCache(valkeyClient),
		dependencyContextCache: valkeyinfra.NewDependencyContextCache(valkeyClient),
	}
	if pool != nil {
		secretCodec, err := upstreamSecretCodec(cfg)
		if err != nil {
			deps.close()
			return nil, err
		}
		deps.tenantRepo = postgres.NewTenantRepository(pool)
		deps.policyRepo = postgres.NewPolicyRepository(pool)
		deps.policyRevisionRepo = postgres.NewPolicyRevisionRepository(pool)
		deps.decisionRepo = postgres.NewDecisionRepository(pool)
		deps.dependencyGraphRepo = postgres.NewDependencyGraphRepository(pool)
		deps.dependencyGraphQueue = deps.dependencyGraphRepo
		deps.dependencyGraphContexts = deps.dependencyGraphRepo
		deps.auditRepo = postgres.NewAuditEventRepository(pool)
		upstreamRepo := postgres.NewUpstreamRepository(pool, secretCodec)
		deps.upstreamRepo = upstreamRepo
		deps.bundleUpstreamRepo = upstreamRepo
		deps.authSecretRewrapper = upstreamRepo
	}

	osvEnricher := osv.NewClient(telemetry.WrapHTTPClient(newOutboundHTTPClient(0)), logger)
	scorecardClient := scorecard.NewClient(telemetry.WrapHTTPClient(newOutboundHTTPClient(0)), logger)
	npmEnricher := npm.NewMetadataEnricher(telemetry.WrapHTTPClient(newOutboundHTTPClient(0)), logger, scorecardClient)
	deps.enricher = enrichment.NewCompositeEnricher(logger, osvEnricher, npmEnricher)

	ociOptions, err := ociClientOptions(cfg)
	if err != nil {
		deps.close()
		return nil, err
	}
	baseOCIClient := upstream.NewOCIClient(telemetry.WrapHTTPClient(newOutboundHTTPClient(0)), ociOptions...)
	deps.ociClient = baseOCIClient
	if cfg.OCICache.Enabled {
		artifactCache, err := newOCIArtifactCache(cfg.OCICache)
		if err != nil {
			deps.close()
			return nil, fmt.Errorf("creating OCI cache: %w", err)
		}
		deps.ociClient = upstream.NewCachedOCIClient(baseOCIClient, artifactCache, logger)
	}
	deps.npmClient = upstream.NewNPMClient(telemetry.WrapHTTPClient(newOutboundHTTPClient(30 * time.Second)))

	return deps, nil
}

func ociClientOptions(cfg *config.Config) ([]upstream.OCIClientOption, error) {
	if cfg.Bundle.TLS.Mode != "mtls" {
		return nil, nil
	}
	if cfg.Runtime.Mode != config.RuntimeModeProxy && cfg.Runtime.Mode != config.RuntimeModeAllInOne {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.Bundle.TLS.CertFile, cfg.Bundle.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading proxy certificate private key for upstream auth: %w", err)
	}
	if cert.PrivateKey == nil {
		return nil, fmt.Errorf("proxy certificate private key is missing")
	}
	resolver := secrets.NewHybridPrivateKeyResolver(cert.PrivateKey)
	if cfg.Runtime.Mode == config.RuntimeModeProxy {
		resolver = secrets.NewStrictHybridPrivateKeyResolver(cert.PrivateKey)
	}
	return []upstream.OCIClientOption{
		upstream.WithAuthSecretResolver(resolver),
	}, nil
}

func upstreamSecretCodec(cfg *config.Config) (*secrets.AESGCMCodec, error) {
	key := strings.TrimSpace(cfg.Secrets.UpstreamAuthKey)
	if key == "" {
		return nil, nil
	}
	codec, err := secrets.NewAESGCMCodecFromBase64(key)
	if err != nil {
		return nil, fmt.Errorf("configuring upstream auth secret codec: %w", err)
	}
	return codec, nil
}

func (d *dependencies) close() {
	if d == nil {
		return
	}
	if d.valkeyClient != nil {
		d.valkeyClient.Close()
	}
	if d.pool != nil {
		d.pool.Close()
	}
}

// installRuntimeServices wires the audit and enrichment services for one
// logical runtime (control-plane or proxy). Each runtime calls this exactly
// once with the appropriate audit read-side repository and write-side recorder
// for its mode.
func installRuntimeServices(
	cfg *config.Config,
	logger *slog.Logger,
	deps *dependencies,
	auditRepo port.AuditEventRepository,
	postgresRecorder port.AuditEventRecorder,
) {
	deps.auditService = newAuditService(cfg, logger, auditRepo, postgresRecorder)
	deps.enrichmentService = newEnrichmentService(deps, logger)
}

func newAuditService(
	cfg *config.Config,
	logger *slog.Logger,
	repo port.AuditEventRepository,
	postgresRecorder port.AuditEventRecorder,
) *service.AuditService {
	recorders := configuredAuditRecorders(cfg, logger, postgresRecorder)
	return service.NewAuditService(
		auditinfra.NewFanoutRecorder(recorders...),
		repo,
		logger,
		cfg.Audit.Enabled,
		parseAuditFailureMode(cfg.Audit.FailureMode),
		parseAuditDetailLevel(cfg.Audit.DetailLevel),
	)
}

func configuredAuditRecorders(
	cfg *config.Config,
	logger *slog.Logger,
	postgresRecorder port.AuditEventRecorder,
) []port.AuditEventRecorder {
	recorders := make([]port.AuditEventRecorder, 0, 2)
	if cfg.Audit.Enabled && cfg.Audit.Slog {
		recorders = append(recorders, auditinfra.NewSlogRecorder(logger))
	}
	if cfg.Audit.Enabled && cfg.Audit.Postgres && postgresRecorder != nil {
		recorders = append(recorders, postgresRecorder)
	}
	return recorders
}

func newEnrichmentService(deps *dependencies, logger *slog.Logger) *service.EnrichmentService {
	return service.NewEnrichmentService(deps.enricher, deps.metadataCache, logger, deps.auditService)
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
