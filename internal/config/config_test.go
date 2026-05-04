package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Run("valid config passes", func(t *testing.T) {
		cfg := validConfig()
		require.NoError(t, cfg.Validate())
	})

	t.Run("invalid server port fails", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.Port = 0

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server.port")
	})

	t.Run("invalid log level fails", func(t *testing.T) {
		cfg := validConfig()
		cfg.Log.Level = "trace"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "log.level")
	})

	t.Run("blank valkey address fails", func(t *testing.T) {
		cfg := validConfig()
		cfg.Valkey.Addr = "   "

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valkey.addr")
	})

	t.Run("invalid proxy health url fails", func(t *testing.T) {
		cfg := validConfig()
		cfg.Health.ProxyURL = "not-a-url"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "health.proxy_url")
	})

	t.Run("enabled telemetry requires endpoint", func(t *testing.T) {
		cfg := validConfig()
		cfg.Telemetry.Enabled = true
		cfg.Telemetry.Endpoint = " "

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "telemetry.endpoint")
	})

	t.Run("enabled telemetry allows stdout only", func(t *testing.T) {
		cfg := validConfig()
		cfg.Telemetry.Enabled = true
		cfg.Telemetry.Endpoint = " "
		cfg.Telemetry.Stdout = true

		require.NoError(t, cfg.Validate())
	})

	t.Run("enabled telemetry requires absolute endpoint url", func(t *testing.T) {
		cfg := validConfig()
		cfg.Telemetry.Enabled = true
		cfg.Telemetry.Endpoint = "localhost:4317"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "telemetry.endpoint")
	})

	t.Run("max idle conns cannot exceed max open conns", func(t *testing.T) {
		cfg := validConfig()
		cfg.Database.MaxOpenConns = 10
		cfg.Database.MaxIdleConns = 11

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database.max_idle_conns")
		assert.Contains(t, err.Error(), "database.max_open_conns")
	})

	t.Run("zero write timeout is allowed for streaming responses", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.WriteTimeout = 0

		require.NoError(t, cfg.Validate())
	})

	t.Run("enabled disk OCI cache requires a root directory", func(t *testing.T) {
		cfg := validConfig()
		cfg.OCICache.Enabled = true
		cfg.OCICache.Backend = "disk"
		cfg.OCICache.RootDir = "   "

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "oci_cache.root_dir")
	})

	t.Run("control-plane mode requires bundle listen address", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeControlPlane
		cfg.Bundle.ListenAddr = " "

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bundle.listen_addr")
	})

	t.Run("all-in-one mode does not require bundle listen address", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeAllInOne
		cfg.Bundle.ListenAddr = " "

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("proxy mode requires control-plane bundle address", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeProxy
		cfg.Bundle.ControlPlaneAddr = " "

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bundle.control_plane_addr")
	})

	t.Run("proxy mode does not require database settings", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeProxy
		cfg.Database = DatabaseConfig{}

		require.NoError(t, cfg.Validate())
	})

	t.Run("control-plane mode requires database settings", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeControlPlane
		cfg.Database = DatabaseConfig{}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database.dsn")
	})
}

func validConfig() *Config {
	return &Config{
		Runtime: RuntimeConfig{
			Mode: RuntimeModeAllInOne,
		},
		Server: ServerConfig{
			Port:         8080,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 0,
			IdleTimeout:  120 * time.Second,
		},
		OCICache: OCICacheConfig{
			Backend: "disk",
			RootDir: defaultOCICacheRootDir(),
		},
		Database: DatabaseConfig{
			DSN:             "postgres://localhost:5432/firewall?sslmode=disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Valkey: ValkeyConfig{
			Addr: "localhost:6379",
			DB:   0,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Telemetry: TelemetryConfig{
			Enabled:     false,
			Endpoint:    "http://localhost:4317",
			Protocol:    "grpc",
			Insecure:    true,
			SampleRatio: 1,
			Stdout:      false,
		},
		Audit: AuditConfig{
			Enabled:     true,
			Slog:        true,
			Postgres:    true,
			FailureMode: "fail_closed",
			DetailLevel: "summary",
		},
		Health: HealthConfig{},
		Bundle: BundleConfig{
			ListenAddr:       ":9090",
			ControlPlaneAddr: "127.0.0.1:9090",
			RefreshInterval:  30 * time.Second,
		},
	}
}
