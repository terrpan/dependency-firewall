// Package config provides application configuration loading and validation.
package config

import (
	"fmt"
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
	Server   ServerConfig   `mapstructure:"server" validate:"required"`
	OCICache OCICacheConfig `mapstructure:"oci_cache"`
	Database DatabaseConfig `mapstructure:"database" validate:"required"`
	Valkey   ValkeyConfig   `mapstructure:"valkey" validate:"required"`
	Log      LogConfig      `mapstructure:"log" validate:"required"`
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
	DSN             string        `mapstructure:"dsn" validate:"notblank"`
	MaxOpenConns    int           `mapstructure:"max_open_conns" validate:"gt=0"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns" validate:"gte=0"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime" validate:"gt=0"`
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

// Load reads configuration from environment variables and an optional
// config.yaml file, applies sensible defaults, and returns a validated Config.
func Load() (*Config, error) {
	v := viper.New()

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

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

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

	if c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("invalid config: field %q must be less than or equal to %q", "database.max_idle_conns", "database.max_open_conns")
	}
	if c.OCICache.Enabled && strings.EqualFold(c.OCICache.Backend, "disk") && strings.TrimSpace(c.OCICache.RootDir) == "" {
		return fmt.Errorf("invalid config: field %q is required when OCI cache backend is %q", "oci_cache.root_dir", "disk")
	}

	return nil
}
