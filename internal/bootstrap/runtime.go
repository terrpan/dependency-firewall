package bootstrap

import (
	"context"
	"log/slog"

	"github.com/danielterry/dependency-firewall/internal/config"
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
	case config.RuntimeModeDependencyGraphWorker:
		info.ServiceName = "dependency-firewall-dependency-graph-worker"
		return RunDependencyGraphWorker(ctx, cfg, logger, info)
	default:
		info.ServiceName = "dependency-firewall"
		return RunAllInOne(ctx, cfg, logger, info)
	}
}
