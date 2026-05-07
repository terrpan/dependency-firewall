// telemetry.go starts and stops OpenTelemetry providers for each runtime mode.
package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

func startTelemetry(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	info BuildInfo,
) (*telemetry.Provider, *slog.Logger, error) {
	provider, err := telemetry.Start(
		ctx,
		cfg.Telemetry,
		info.ServiceName,
		info.Version,
		info.Commit,
		info.BuildTime,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("starting telemetry: %w", err)
	}

	wrappedLogger := telemetry.WrapLogger(logger)
	slog.SetDefault(wrappedLogger)

	return provider, wrappedLogger, nil
}

func shutdownTelemetry(provider *telemetry.Provider) {
	if provider == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = provider.Shutdown(ctx)
}
