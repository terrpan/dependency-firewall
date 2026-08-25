package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
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
		cfg.Bundle.TLS = validProxyTLSConfig()

		require.NoError(t, cfg.Validate())
	})

	t.Run("dependency graph worker mode does not require database settings", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeDependencyGraphWorker
		cfg.Database = DatabaseConfig{}
		cfg.Bundle.TLS = validProxyTLSConfig()

		require.NoError(t, cfg.Validate())
	})

	t.Run("dependency graph worker mode requires mtls bundle mode", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeDependencyGraphWorker

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bundle.tls.mode")
	})

	t.Run("enabled dependency graph worker requires tenant scope", func(t *testing.T) {
		cfg := validConfig()
		cfg.DependencyGraph.Enabled = true
		cfg.DependencyGraph.TenantID = " "

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dependency_graph.tenant_id")
	})

	t.Run("control-plane mode requires database settings", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeControlPlane
		cfg.Database = DatabaseConfig{}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database.dsn")
	})

	t.Run("upstream auth key must be base64 encoded 32 byte key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Secrets.UpstreamAuthKey = base64.StdEncoding.EncodeToString([]byte("short"))

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secrets.upstream_auth_key")
	})

	t.Run("mtls bundle mode requires certificate files", func(t *testing.T) {
		cfg := validConfig()
		cfg.Bundle.TLS.Mode = "mtls"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bundle.tls.ca_file")
	})

	t.Run("mtls bundle mode accepts certificate files", func(t *testing.T) {
		cfg := validConfig()
		cfg.Bundle.TLS = validProxyTLSConfig()

		require.NoError(t, cfg.Validate())
	})

	t.Run("proxy mode requires mtls bundle mode", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeProxy

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bundle.tls.mode")
	})

	t.Run("control-plane mtls requires authorized clients", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeControlPlane
		cfg.Bundle.TLS = validProxyTLSConfig()

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bundle.tls.authorized_clients")
	})

	t.Run("control-plane mtls accepts authorized clients", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeControlPlane
		cfg.Bundle.TLS = validControlPlaneTLSConfig()

		require.NoError(t, cfg.Validate())
	})

	t.Run("control-plane insecure bundle mode requires explicit override", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeControlPlane
		cfg.Bundle.TLS.Mode = "insecure"
		cfg.Bundle.TLS.AllowInsecureControlPlane = false

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bundle.tls.allow_insecure_control_plane")
	})

	t.Run("control-plane insecure bundle mode accepts explicit override", func(t *testing.T) {
		cfg := validConfig()
		cfg.Runtime.Mode = RuntimeModeControlPlane
		cfg.Bundle.TLS.Mode = "insecure"
		cfg.Bundle.TLS.AllowInsecureControlPlane = true

		require.NoError(t, cfg.Validate())
	})

	t.Run("additional enrollment CA bundle is proxy-only", func(t *testing.T) {
		cfg := validConfig()
		cfg.Enrollment.AdditionalCAFile = "/run/secrets/internal-root.pem"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enrollment.additional_ca_file")
	})
}

func TestLoadWithOptions_AppliesEnvironmentOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
runtime:
  mode: proxy
telemetry:
  enabled: false
  endpoint: "http://file-collector:4317"
  protocol: grpc
  insecure: true
server:
  port: 8080
bundle:
  tls:
    mode: mtls
    ca_file: "/run/secrets/control-plane-ca.pem"
    cert_file: "/run/secrets/proxy.pem"
    key_file: "/run/secrets/proxy-key.pem"
enrollment:
  additional_ca_file: "/etc/firewall/ca-from-file.pem"
`), 0o600))

	t.Setenv("FIREWALL_TELEMETRY_ENABLED", "true")
	t.Setenv("FIREWALL_TELEMETRY_ENDPOINT", "http://otel-collector:4317")
	t.Setenv("FIREWALL_TELEMETRY_INSECURE", "false")
	t.Setenv("FIREWALL_SERVER_PORT", "18080")
	t.Setenv("FIREWALL_BUNDLE_TLS_ALLOW_INSECURE_CONTROL_PLANE", "true")
	t.Setenv("FIREWALL_ENROLLMENT_ADDITIONAL_CA_FILE", "/run/secrets/internal-root.pem")

	cfg, err := LoadWithOptions(LoadOptions{ConfigPath: configPath})
	require.NoError(t, err)

	assert.True(t, cfg.Telemetry.Enabled)
	assert.Equal(t, "http://otel-collector:4317", cfg.Telemetry.Endpoint)
	assert.False(t, cfg.Telemetry.Insecure)
	assert.Equal(t, 18080, cfg.Server.Port)
	assert.True(t, cfg.Bundle.TLS.AllowInsecureControlPlane)
	assert.Equal(t, "/run/secrets/internal-root.pem", cfg.Enrollment.AdditionalCAFile)
	assert.Equal(t, "*", cfg.DependencyGraph.TenantID)
}

func validProxyTLSConfig() BundleTLSConfig {
	return BundleTLSConfig{
		Mode:     "mtls",
		CAFile:   "ca.pem",
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}
}

func validControlPlaneTLSConfig() BundleTLSConfig {
	cfg := validProxyTLSConfig()
	cfg.AuthorizedClients = []BundleTLSAuthorizedClient{{
		Identity:  "spiffe://dependency-firewall/proxy/default",
		TenantIDs: []string{"tenant-1"},
	}}
	return cfg
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
			TLS: BundleTLSConfig{
				Mode: "insecure",
			},
		},
	}
}
