// Package config provides application configuration loading and validation.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/danielterry/dependency-firewall/internal/validation"
)

var configValidator = validation.New("mapstructure")

func defaultOCICacheRootDir() string {
	return filepath.Join(os.TempDir(), "dependency-firewall", "oci")
}

// Config holds all application configuration sections.
type Config struct {
	Runtime   RuntimeConfig   `mapstructure:"runtime" validate:"required"`
	Server    ServerConfig    `mapstructure:"server" validate:"required"`
	OCICache  OCICacheConfig  `mapstructure:"oci_cache"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Valkey    ValkeyConfig    `mapstructure:"valkey" validate:"required"`
	Log       LogConfig       `mapstructure:"log" validate:"required"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
	Audit     AuditConfig     `mapstructure:"audit" validate:"required"`
	Health    HealthConfig    `mapstructure:"health"`
	Bundle    BundleConfig    `mapstructure:"bundle" validate:"required"`
}

// RuntimeMode identifies which service shape the single binary should run.
type RuntimeMode string

const (
	RuntimeModeAllInOne     RuntimeMode = "all-in-one"
	RuntimeModeControlPlane RuntimeMode = "control-plane"
	RuntimeModeProxy        RuntimeMode = "proxy"
)

// RuntimeConfig holds process mode selection.
type RuntimeConfig struct {
	Mode RuntimeMode `mapstructure:"mode" validate:"required,oneof=all-in-one control-plane proxy"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port         int           `mapstructure:"port" validate:"gte=1,lte=65535"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" validate:"gt=0"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" validate:"gte=0"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" validate:"gt=0"`
}

// OCICacheConfig holds OCI artifact cache settings.
type OCICacheConfig struct {
	Enabled    bool              `mapstructure:"enabled"`
	Backend    string            `mapstructure:"backend" validate:"omitempty,oneof=disk s3 gcs"`
	RootDir    string            `mapstructure:"root_dir"`
	MaxBytes   int64             `mapstructure:"max_bytes" validate:"gte=0"`
	MaxAge     time.Duration     `mapstructure:"max_age" validate:"gte=0"`
	MaxEntries int               `mapstructure:"max_entries" validate:"gte=0"`
	S3         OCICacheS3Config  `mapstructure:"s3"`
	GCS        OCICacheGCSConfig `mapstructure:"gcs"`
}

// OCICacheS3Config reserves config for a future S3-backed OCI cache.
type OCICacheS3Config struct {
	Bucket   string `mapstructure:"bucket"`
	Prefix   string `mapstructure:"prefix"`
	Region   string `mapstructure:"region"`
	Endpoint string `mapstructure:"endpoint"`
}

// OCICacheGCSConfig reserves config for a future GCS-backed OCI cache.
type OCICacheGCSConfig struct {
	Bucket string `mapstructure:"bucket"`
	Prefix string `mapstructure:"prefix"`
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// ValkeyConfig holds Valkey connection settings.
type ValkeyConfig struct {
	Addr     string `mapstructure:"addr" validate:"notblank"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db" validate:"gte=0"`
}

// LogConfig holds structured logging settings.
type LogConfig struct {
	Level  string `mapstructure:"level" validate:"oneof=debug info warn error"`
	Format string `mapstructure:"format" validate:"oneof=json text"`
}

// TelemetryConfig holds OpenTelemetry tracing settings.
type TelemetryConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	Endpoint    string            `mapstructure:"endpoint"`
	Protocol    string            `mapstructure:"protocol" validate:"omitempty,oneof=grpc http/protobuf"`
	Insecure    bool              `mapstructure:"insecure"`
	SampleRatio float64           `mapstructure:"sample_ratio" validate:"gte=0,lte=1"`
	Stdout      bool              `mapstructure:"stdout"`
	Headers     map[string]string `mapstructure:"headers"`
	SQLTracing  SQLTracingConfig  `mapstructure:"sql_tracing"`
}

// SQLTracingConfig holds settings for SQL query tracing.
type SQLTracingConfig struct {
	TrimSQLInSpanName               bool `mapstructure:"trim_sql_in_span_name"`
	DisableSQLStatementInAttributes bool `mapstructure:"disable_sql_statement_in_attributes"`
}

// AuditConfig holds audit-specific capture and durability settings.
type AuditConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Slog        bool   `mapstructure:"slog"`
	Postgres    bool   `mapstructure:"postgres"`
	FailureMode string `mapstructure:"failure_mode" validate:"oneof=fail_open fail_closed"`
	DetailLevel string `mapstructure:"detail_level" validate:"oneof=minimal summary full"`
}

// HealthConfig holds optional runtime health integration settings.
type HealthConfig struct {
	ProxyURL string `mapstructure:"proxy_url"`
}

// BundleConfig holds control-plane bundle gRPC and proxy refresh settings.
type BundleConfig struct {
	ListenAddr       string        `mapstructure:"listen_addr"`
	ControlPlaneAddr string        `mapstructure:"control_plane_addr"`
	RefreshInterval  time.Duration `mapstructure:"refresh_interval" validate:"gte=0"`
}

// LoadOptions customizes config loading behavior.
type LoadOptions struct {
	ConfigPath string
}

// Load reads configuration from environment variables and an optional
// config.yaml file, applies sensible defaults, and returns a validated Config.
func Load() (*Config, error) {
	return LoadWithOptions(LoadOptions{})
}

// LoadWithOptions reads configuration with optional loader overrides.
func LoadWithOptions(options LoadOptions) (*Config, error) {
	v := viper.New()

	v.SetDefault("runtime.mode", string(RuntimeModeAllInOne))
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 5*time.Second)
	v.SetDefault("server.write_timeout", 0)
	v.SetDefault("server.idle_timeout", 120*time.Second)

	v.SetDefault("oci_cache.enabled", false)
	v.SetDefault("oci_cache.backend", "disk")
	v.SetDefault("oci_cache.root_dir", defaultOCICacheRootDir())
	v.SetDefault("oci_cache.max_bytes", int64(0))
	v.SetDefault("oci_cache.max_age", 0)
	v.SetDefault("oci_cache.max_entries", 0)
	v.SetDefault("oci_cache.s3.bucket", "")
	v.SetDefault("oci_cache.s3.prefix", "")
	v.SetDefault("oci_cache.s3.region", "")
	v.SetDefault("oci_cache.s3.endpoint", "")
	v.SetDefault("oci_cache.gcs.bucket", "")
	v.SetDefault("oci_cache.gcs.prefix", "")

	v.SetDefault("database.dsn", "postgres://localhost:5432/firewall?sslmode=disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", 5*time.Minute)

	v.SetDefault("valkey.addr", "localhost:6379")
	v.SetDefault("valkey.password", "")
	v.SetDefault("valkey.db", 0)

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("telemetry.enabled", false)
	v.SetDefault("telemetry.endpoint", "http://localhost:4317")
	v.SetDefault("telemetry.protocol", "grpc")
	v.SetDefault("telemetry.insecure", true)
	v.SetDefault("telemetry.sample_ratio", 1.0)
	v.SetDefault("telemetry.stdout", false)
	v.SetDefault("telemetry.headers", map[string]string{})
	v.SetDefault("telemetry.sql_tracing.trim_sql_in_span_name", true)
	v.SetDefault("telemetry.sql_tracing.disable_sql_statement_in_attributes", true)
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.slog", true)
	v.SetDefault("audit.postgres", true)
	v.SetDefault("audit.failure_mode", "fail_closed")
	v.SetDefault("audit.detail_level", "summary")
	v.SetDefault("health.proxy_url", "")
	v.SetDefault("bundle.listen_addr", ":9090")
	v.SetDefault("bundle.control_plane_addr", "127.0.0.1:9090")
	v.SetDefault("bundle.refresh_interval", 30*time.Second)

	if strings.TrimSpace(options.ConfigPath) != "" {
		v.SetConfigFile(options.ConfigPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		// A missing config file is acceptable; other read errors are not.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	v.SetEnvPrefix("FIREWALL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate validates the configuration after file and environment decoding.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("invalid config: config is required")
	}

	if err := configValidator.Struct(c); err != nil {
		return fmt.Errorf("invalid config: %s", validation.ErrorMessage(err))
	}

	if c.Runtime.Mode != RuntimeModeProxy {
		if strings.TrimSpace(c.Database.DSN) == "" {
			return fmt.Errorf("invalid config: field %q is required when runtime.mode is %q", "database.dsn", c.Runtime.Mode)
		}
		if c.Database.MaxOpenConns <= 0 {
			return fmt.Errorf("invalid config: field %q must be greater than 0", "database.max_open_conns")
		}
		if c.Database.MaxIdleConns < 0 {
			return fmt.Errorf("invalid config: field %q must be greater than or equal to 0", "database.max_idle_conns")
		}
		if c.Database.ConnMaxLifetime <= 0 {
			return fmt.Errorf("invalid config: field %q must be greater than 0", "database.conn_max_lifetime")
		}
	}
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns && c.Database.MaxOpenConns > 0 {
		return fmt.Errorf("invalid config: field %q must be less than or equal to %q", "database.max_idle_conns", "database.max_open_conns")
	}
	if c.OCICache.Enabled && strings.EqualFold(c.OCICache.Backend, "disk") && strings.TrimSpace(c.OCICache.RootDir) == "" {
		return fmt.Errorf("invalid config: field %q is required when OCI cache backend is %q", "oci_cache.root_dir", "disk")
	}
	if proxyURL := strings.TrimSpace(c.Health.ProxyURL); proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid config: field %q must be a valid absolute URL", "health.proxy_url")
		}
	}
	if c.Telemetry.Enabled {
		endpoint := strings.TrimSpace(c.Telemetry.Endpoint)
		if endpoint == "" && !c.Telemetry.Stdout {
			return fmt.Errorf("invalid config: either %q must be set or %q must be true when telemetry is enabled", "telemetry.endpoint", "telemetry.stdout")
		}
		if endpoint != "" {
			parsed, err := url.Parse(endpoint)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return fmt.Errorf("invalid config: field %q must be a valid absolute URL without query or fragment", "telemetry.endpoint")
			}
		}
	}
	switch c.Runtime.Mode {
	case RuntimeModeControlPlane:
		if strings.TrimSpace(c.Bundle.ListenAddr) == "" {
			return fmt.Errorf("invalid config: field %q is required when runtime.mode is %q", "bundle.listen_addr", c.Runtime.Mode)
		}
	}
	switch c.Runtime.Mode {
	case RuntimeModeAllInOne, RuntimeModeProxy:
		if strings.TrimSpace(c.Bundle.ControlPlaneAddr) == "" {
			return fmt.Errorf("invalid config: field %q is required when runtime.mode is %q", "bundle.control_plane_addr", c.Runtime.Mode)
		}
	}

	return nil
}
