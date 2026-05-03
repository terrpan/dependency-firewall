package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/danielterry/dependency-firewall/internal/bootstrap"
	"github.com/danielterry/dependency-firewall/internal/buildinfo"
	"github.com/danielterry/dependency-firewall/internal/config"
)

var (
	ldVersion   = "dev"
	ldCommit    = "unknown"
	ldBuildTime = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var configPath string
	var mode string
	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.StringVar(&mode, "mode", "", "runtime mode: all-in-one, control-plane, or proxy")
	flag.Parse()

	cfg, err := config.LoadWithOptions(config.LoadOptions{ConfigPath: configPath})
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if mode != "" {
		cfg.Runtime.Mode = config.RuntimeMode(mode)
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("applying runtime mode override: %w", err)
		}
	}

	logger := config.SetupLogging(cfg.Log)
	slog.SetDefault(logger)

	info := buildinfo.Read(ldVersion, ldCommit, ldBuildTime)
	return bootstrap.Run(context.Background(), cfg, logger, bootstrap.BuildInfo{
		ServiceName: "dependency-firewall",
		Version:     info.Version,
		Commit:      info.Commit,
		BuildTime:   info.BuildTime,
	})
}
