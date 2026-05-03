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
}

func validConfig() *Config {
	return &Config{
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
		Audit: AuditConfig{
			Enabled:     true,
			Slog:        true,
			Postgres:    true,
			FailureMode: "fail_closed",
			DetailLevel: "summary",
		},
	}
}
