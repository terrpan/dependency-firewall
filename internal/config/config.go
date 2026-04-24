// Package config provides application configuration loading and validation.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/danielterry/dependency-firewall/internal/validation"
)

var configValidator = validation.New("mapstructure")

// Config holds all application configuration sections.
type Config struct {
	Server   ServerConfig   `mapstructure:"server" validate:"required"`
	Database DatabaseConfig `mapstructure:"database" validate:"required"`
	Valkey   ValkeyConfig   `mapstructure:"valkey" validate:"required"`
	Log      LogConfig      `mapstructure:"log" validate:"required"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port         int           `mapstructure:"port" validate:"gte=1,lte=65535"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" validate:"gt=0"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" validate:"gt=0"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" validate:"gt=0"`
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
	v.SetDefault("server.write_timeout", 10*time.Second)
	v.SetDefault("server.idle_timeout", 120*time.Second)

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

	return nil
}
