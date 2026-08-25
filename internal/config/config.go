// Package config provides application configuration loading and validation.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
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
	Runtime         RuntimeConfig         `mapstructure:"runtime"          validate:"required"`
	Server          ServerConfig          `mapstructure:"server"           validate:"required"`
	OCICache        OCICacheConfig        `mapstructure:"oci_cache"`
	Database        DatabaseConfig        `mapstructure:"database"`
	Valkey          ValkeyConfig          `mapstructure:"valkey"           validate:"required"`
	Log             LogConfig             `mapstructure:"log"              validate:"required"`
	Telemetry       TelemetryConfig       `mapstructure:"telemetry"`
	Audit           AuditConfig           `mapstructure:"audit"            validate:"required"`
	Health          HealthConfig          `mapstructure:"health"`
	Bundle          BundleConfig          `mapstructure:"bundle"           validate:"required"`
	Secrets         SecretsConfig         `mapstructure:"secrets"`
	DependencyGraph DependencyGraphConfig `mapstructure:"dependency_graph"`
	Enrollment      EnrollmentConfig      `mapstructure:"enrollment"`
}

// RuntimeMode identifies which service shape the single binary should run.
type RuntimeMode string

// The runtime mode selects which halves of the system the process starts: the
// control plane owns policy and durable state, the proxy serves package traffic,
// and the dependency-graph worker drains the async npm resolve queue.
const (
	RuntimeModeAllInOne              RuntimeMode = "all-in-one"
	RuntimeModeControlPlane          RuntimeMode = "control-plane"
	RuntimeModeProxy                 RuntimeMode = "proxy"
	RuntimeModeDependencyGraphWorker RuntimeMode = "dependency-graph-worker"
)

// RuntimeConfig holds process mode selection.
type RuntimeConfig struct {
	Mode RuntimeMode `mapstructure:"mode" validate:"required,oneof=all-in-one control-plane proxy dependency-graph-worker"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port         int           `mapstructure:"port"          validate:"gte=1,lte=65535"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"  validate:"gt=0"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" validate:"gte=0"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"  validate:"gt=0"`
}

// OCICacheConfig holds OCI artifact cache settings.
type OCICacheConfig struct {
	Enabled    bool              `mapstructure:"enabled"`
	Backend    string            `mapstructure:"backend"     validate:"omitempty,oneof=disk s3 gcs"`
	RootDir    string            `mapstructure:"root_dir"`
	MaxBytes   int64             `mapstructure:"max_bytes"   validate:"gte=0"`
	MaxAge     time.Duration     `mapstructure:"max_age"     validate:"gte=0"`
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
	Addr     string `mapstructure:"addr"     validate:"notblank"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"       validate:"gte=0"`
}

// LogConfig holds structured logging settings.
type LogConfig struct {
	Level  string `mapstructure:"level"  validate:"oneof=debug info warn error"`
	Format string `mapstructure:"format" validate:"oneof=json text"`
}

// TelemetryConfig holds OpenTelemetry tracing settings.
type TelemetryConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	Endpoint    string            `mapstructure:"endpoint"`
	Protocol    string            `mapstructure:"protocol"     validate:"omitempty,oneof=grpc http/protobuf"`
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
	ListenAddr       string          `mapstructure:"listen_addr"`
	ControlPlaneAddr string          `mapstructure:"control_plane_addr"`
	RefreshInterval  time.Duration   `mapstructure:"refresh_interval"   validate:"gte=0"`
	TLS              BundleTLSConfig `mapstructure:"tls"`
}

// BundleTLSConfig holds control-plane gRPC transport security settings.
type BundleTLSConfig struct {
	Mode                      string                      `mapstructure:"mode"                         validate:"oneof=insecure mtls"`
	CAFile                    string                      `mapstructure:"ca_file"`
	CertFile                  string                      `mapstructure:"cert_file"`
	KeyFile                   string                      `mapstructure:"key_file"`
	ServerNameOverride        string                      `mapstructure:"server_name_override"`
	AllowInsecureControlPlane bool                        `mapstructure:"allow_insecure_control_plane"`
	AuthorizedClients         []BundleTLSAuthorizedClient `mapstructure:"authorized_clients"`
}

// BundleTLSAuthorizedClient maps one mTLS client certificate identity to tenant access.
type BundleTLSAuthorizedClient struct {
	Identity  string   `mapstructure:"identity"`
	TenantIDs []string `mapstructure:"tenant_ids"`
}

// SecretsConfig holds application-managed secret settings.
type SecretsConfig struct {
	UpstreamAuthKey string `mapstructure:"upstream_auth_key"`
}

// EnrollmentConfig configures optional automatic split-proxy enrollment.
type EnrollmentConfig struct {
	Enabled                 bool          `mapstructure:"enabled"`
	PublicAPIURL            string        `mapstructure:"public_api_url"`
	AdditionalCAFile        string        `mapstructure:"additional_ca_file"`
	VerificationURI         string        `mapstructure:"verification_uri"`
	PublicGRPCAddress       string        `mapstructure:"public_grpc_address"`
	GRPCServerName          string        `mapstructure:"grpc_server_name"`
	HMACKey                 string        `mapstructure:"hmac_key"`
	Validity                time.Duration `mapstructure:"validity"`
	PollInterval            time.Duration `mapstructure:"poll_interval"`
	IssuerCACertificateFile string        `mapstructure:"issuer_ca_certificate_file"`
	IssuerCAPrivateKeyFile  string        `mapstructure:"issuer_ca_private_key_file"`
	CertificateValidity     time.Duration `mapstructure:"certificate_validity"`
}

// DependencyGraphConfig holds async npm dependency graph resolver settings.
type DependencyGraphConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	RunInProcess bool          `mapstructure:"run_in_process"`
	TenantID     string        `mapstructure:"tenant_id"`
	PollInterval time.Duration `mapstructure:"poll_interval"`
	Timeout      time.Duration `mapstructure:"timeout"`
	Concurrency  int           `mapstructure:"concurrency"`
	RetryDelay   time.Duration `mapstructure:"retry_delay"`
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
	setDefaults(v)

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
	if err := bindEnvKeys(v); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	setRuntimeServerDefaults(v)
	setOCICacheDefaults(v)
	setStorageDefaults(v)
	setObservabilityDefaults(v)
	setBundleDefaults(v)
	v.SetDefault("secrets.upstream_auth_key", "")
	setDependencyGraphDefaults(v)
	setEnrollmentDefaults(v)
}

func setRuntimeServerDefaults(v *viper.Viper) {
	v.SetDefault("runtime.mode", string(RuntimeModeAllInOne))
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 5*time.Second)
	v.SetDefault("server.write_timeout", 0)
	v.SetDefault("server.idle_timeout", 120*time.Second)
}

func setOCICacheDefaults(v *viper.Viper) {
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
}

func setStorageDefaults(v *viper.Viper) {
	v.SetDefault("database.dsn", "postgres://localhost:5432/firewall?sslmode=disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", 5*time.Minute)
	v.SetDefault("valkey.addr", "localhost:6379")
	v.SetDefault("valkey.password", "")
	v.SetDefault("valkey.db", 0)
}

func setObservabilityDefaults(v *viper.Viper) {
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
}

func setBundleDefaults(v *viper.Viper) {
	v.SetDefault("bundle.listen_addr", ":9090")
	v.SetDefault("bundle.control_plane_addr", "127.0.0.1:9090")
	v.SetDefault("bundle.refresh_interval", 30*time.Second)
	v.SetDefault("bundle.tls.mode", "insecure")
	v.SetDefault("bundle.tls.ca_file", "")
	v.SetDefault("bundle.tls.cert_file", "")
	v.SetDefault("bundle.tls.key_file", "")
	v.SetDefault("bundle.tls.server_name_override", "")
	v.SetDefault("bundle.tls.allow_insecure_control_plane", false)
	v.SetDefault("bundle.tls.authorized_clients", []BundleTLSAuthorizedClient{})
}

func setDependencyGraphDefaults(v *viper.Viper) {
	v.SetDefault("dependency_graph.enabled", true)
	v.SetDefault("dependency_graph.run_in_process", false)
	v.SetDefault("dependency_graph.tenant_id", "*")
	v.SetDefault("dependency_graph.poll_interval", 5*time.Second)
	v.SetDefault("dependency_graph.timeout", 2*time.Minute)
	v.SetDefault("dependency_graph.concurrency", 2)
	v.SetDefault("dependency_graph.retry_delay", 5*time.Minute)
}

func setEnrollmentDefaults(v *viper.Viper) {
	v.SetDefault("enrollment.enabled", false)
	v.SetDefault("enrollment.public_api_url", "")
	v.SetDefault("enrollment.additional_ca_file", "")
	v.SetDefault("enrollment.verification_uri", "")
	v.SetDefault("enrollment.public_grpc_address", "")
	v.SetDefault("enrollment.grpc_server_name", "")
	v.SetDefault("enrollment.hmac_key", "")
	v.SetDefault("enrollment.validity", 10*time.Minute)
	v.SetDefault("enrollment.poll_interval", 5*time.Second)
	v.SetDefault("enrollment.issuer_ca_certificate_file", "")
	v.SetDefault("enrollment.issuer_ca_private_key_file", "")
	v.SetDefault("enrollment.certificate_validity", 30*24*time.Hour)
}

func bindEnvKeys(v *viper.Viper) error {
	for _, key := range v.AllKeys() {
		if err := v.BindEnv(key); err != nil {
			return fmt.Errorf("binding environment variable for %q: %w", key, err)
		}
	}
	return nil
}

// Validate validates the configuration after file and environment decoding.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("invalid config: config is required")
	}
	if err := configValidator.Struct(c); err != nil {
		return fmt.Errorf("invalid config: %s", validation.ErrorMessage(err))
	}
	if err := c.validateDatabase(); err != nil {
		return err
	}
	if err := c.validateDependencyGraph(); err != nil {
		return err
	}
	if err := c.validateOCICache(); err != nil {
		return err
	}
	if err := c.validateHealth(); err != nil {
		return err
	}
	if err := c.validateTelemetry(); err != nil {
		return err
	}
	if err := c.validateSecrets(); err != nil {
		return err
	}
	if err := c.validateBundleTLS(); err != nil {
		return err
	}
	if err := c.validateEnrollment(); err != nil {
		return err
	}
	if err := c.validateControlPlaneBundle(); err != nil {
		return err
	}
	return c.validateBundleClient()
}

func (c *Config) validateDatabase() error {
	if c.Runtime.Mode != RuntimeModeProxy && c.Runtime.Mode != RuntimeModeDependencyGraphWorker {
		if strings.TrimSpace(c.Database.DSN) == "" {
			return fmt.Errorf(
				"invalid config: field %q is required when runtime.mode is %q",
				"database.dsn",
				c.Runtime.Mode,
			)
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
		return fmt.Errorf(
			"invalid config: field %q must be less than or equal to %q",
			"database.max_idle_conns",
			"database.max_open_conns",
		)
	}
	return nil
}

func (c *Config) validateDependencyGraph() error {
	if c.DependencyGraph.Enabled && strings.TrimSpace(c.DependencyGraph.TenantID) == "" {
		return fmt.Errorf(
			"invalid config: field %q is required when dependency graph resolution is enabled",
			"dependency_graph.tenant_id",
		)
	}
	return nil
}

func (c *Config) validateOCICache() error {
	if c.OCICache.Enabled && strings.EqualFold(c.OCICache.Backend, "disk") &&
		strings.TrimSpace(c.OCICache.RootDir) == "" {
		return fmt.Errorf(
			"invalid config: field %q is required when OCI cache backend is %q",
			"oci_cache.root_dir",
			"disk",
		)
	}
	return nil
}

func (c *Config) validateHealth() error {
	proxyURL := strings.TrimSpace(c.Health.ProxyURL)
	if proxyURL == "" {
		return nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid config: field %q must be a valid absolute URL", "health.proxy_url")
	}
	return nil
}

func (c *Config) validateTelemetry() error {
	if !c.Telemetry.Enabled {
		return nil
	}
	endpoint := strings.TrimSpace(c.Telemetry.Endpoint)
	if endpoint == "" && !c.Telemetry.Stdout {
		return fmt.Errorf(
			"invalid config: either %q must be set or %q must be true when telemetry is enabled",
			"telemetry.endpoint",
			"telemetry.stdout",
		)
	}
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf(
			"invalid config: field %q must be a valid absolute URL without query or fragment",
			"telemetry.endpoint",
		)
	}
	return nil
}

func (c *Config) validateSecrets() error {
	key := strings.TrimSpace(c.Secrets.UpstreamAuthKey)
	if key == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf(
			"invalid config: field %q must be a base64 encoded 32-byte key",
			"secrets.upstream_auth_key",
		)
	}
	return nil
}

func (c *Config) validateBundleTLS() error {
	if !strings.EqualFold(c.Bundle.TLS.Mode, "mtls") {
		return nil
	}
	automaticProxyCredentials := c.Runtime.Mode == RuntimeModeProxy && c.Enrollment.Enabled
	if strings.TrimSpace(c.Bundle.TLS.CAFile) == "" && !automaticProxyCredentials {
		return fmt.Errorf(
			"invalid config: field %q is required when bundle.tls.mode is %q",
			"bundle.tls.ca_file",
			c.Bundle.TLS.Mode,
		)
	}
	if strings.TrimSpace(c.Bundle.TLS.CertFile) == "" && !automaticProxyCredentials {
		return fmt.Errorf(
			"invalid config: field %q is required when bundle.tls.mode is %q",
			"bundle.tls.cert_file",
			c.Bundle.TLS.Mode,
		)
	}
	if strings.TrimSpace(c.Bundle.TLS.KeyFile) == "" && !automaticProxyCredentials {
		return fmt.Errorf(
			"invalid config: field %q is required when bundle.tls.mode is %q",
			"bundle.tls.key_file",
			c.Bundle.TLS.Mode,
		)
	}
	if c.Runtime.Mode == RuntimeModeControlPlane {
		return c.validateAuthorizedClients()
	}
	return nil
}

func (c *Config) validateAuthorizedClients() error {
	if len(c.Bundle.TLS.AuthorizedClients) == 0 && !c.Enrollment.Enabled {
		return fmt.Errorf(
			"invalid config: field %q is required when runtime.mode is %q and bundle.tls.mode is %q",
			"bundle.tls.authorized_clients",
			c.Runtime.Mode,
			c.Bundle.TLS.Mode,
		)
	}
	for i, client := range c.Bundle.TLS.AuthorizedClients {
		if strings.TrimSpace(client.Identity) == "" {
			return fmt.Errorf(
				"invalid config: field %q is required",
				fmt.Sprintf("bundle.tls.authorized_clients[%d].identity", i),
			)
		}
		if len(client.TenantIDs) == 0 {
			return fmt.Errorf(
				"invalid config: field %q must include at least one tenant id",
				fmt.Sprintf("bundle.tls.authorized_clients[%d].tenant_ids", i),
			)
		}
		for j, tenantID := range client.TenantIDs {
			if strings.TrimSpace(tenantID) == "" {
				return fmt.Errorf(
					"invalid config: field %q must not be blank",
					fmt.Sprintf("bundle.tls.authorized_clients[%d].tenant_ids[%d]", i, j),
				)
			}
		}
	}
	return nil
}

func (c *Config) validateEnrollment() error {
	if err := c.validateEnrollmentAdditionalCA(); err != nil {
		return err
	}
	if !c.Enrollment.Enabled {
		return nil
	}
	if err := c.validateEnrollmentMode(); err != nil {
		return err
	}
	if err := validateEnrollmentURL("enrollment.public_api_url", c.Enrollment.PublicAPIURL); err != nil {
		return err
	}
	if c.Enrollment.Validity <= 0 || c.Enrollment.PollInterval <= 0 || c.Enrollment.CertificateValidity <= 0 {
		return fmt.Errorf("invalid config: enrollment validity, polling, and certificate validity must be positive")
	}
	if c.Runtime.Mode == RuntimeModeProxy {
		return nil
	}
	return c.validateControlPlaneEnrollment()
}

func (c *Config) validateEnrollmentAdditionalCA() error {
	if strings.TrimSpace(c.Enrollment.AdditionalCAFile) == "" || c.Runtime.Mode == RuntimeModeProxy {
		return nil
	}
	return fmt.Errorf(
		"invalid config: field %q is supported only when runtime.mode is %q",
		"enrollment.additional_ca_file",
		RuntimeModeProxy,
	)
}

func (c *Config) validateEnrollmentMode() error {
	switch c.Runtime.Mode {
	case RuntimeModeProxy, RuntimeModeControlPlane:
		return nil
	case RuntimeModeDependencyGraphWorker:
		return fmt.Errorf("invalid config: automatic enrollment is not supported for dependency-graph-worker mode")
	case RuntimeModeAllInOne:
		return fmt.Errorf(
			"invalid config: automatic enrollment is supported only by split control-plane and proxy modes",
		)
	default:
		return fmt.Errorf(
			"invalid config: automatic enrollment is not supported for runtime.mode %q",
			c.Runtime.Mode,
		)
	}
}

func (c *Config) validateControlPlaneEnrollment() error {
	if c.Bundle.TLS.Mode != "mtls" {
		return fmt.Errorf("invalid config: field %q must be %q when enrollment is enabled", "bundle.tls.mode", "mtls")
	}
	for field, value := range map[string]string{
		"enrollment.verification_uri":           c.Enrollment.VerificationURI,
		"enrollment.public_grpc_address":        c.Enrollment.PublicGRPCAddress,
		"enrollment.grpc_server_name":           c.Enrollment.GRPCServerName,
		"enrollment.issuer_ca_certificate_file": c.Enrollment.IssuerCACertificateFile,
		"enrollment.issuer_ca_private_key_file": c.Enrollment.IssuerCAPrivateKeyFile,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("invalid config: field %q is required when enrollment is enabled", field)
		}
	}
	if err := validateEnrollmentURL("enrollment.verification_uri", c.Enrollment.VerificationURI); err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.Enrollment.HMACKey))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("invalid config: field %q must be a base64 encoded 32-byte key", "enrollment.hmac_key")
	}
	return nil
}

func validateEnrollmentURL(field, value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid config: field %q must be an absolute URL without query or fragment", field)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if parsed.Scheme == "http" && (strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("invalid config: field %q must use HTTPS except for loopback development", field)
}

func (c *Config) validateControlPlaneBundle() error {
	if c.Runtime.Mode != RuntimeModeControlPlane {
		return nil
	}
	if strings.TrimSpace(c.Bundle.ListenAddr) == "" {
		return fmt.Errorf(
			"invalid config: field %q is required when runtime.mode is %q",
			"bundle.listen_addr",
			c.Runtime.Mode,
		)
	}
	if c.Bundle.TLS.Mode != "mtls" && !c.Bundle.TLS.AllowInsecureControlPlane {
		return fmt.Errorf(
			"invalid config: field %q must be %q when runtime.mode is %q unless %q is true",
			"bundle.tls.mode",
			"mtls",
			c.Runtime.Mode,
			"bundle.tls.allow_insecure_control_plane",
		)
	}
	return nil
}

func (c *Config) validateBundleClient() error {
	switch c.Runtime.Mode {
	case RuntimeModeAllInOne, RuntimeModeProxy, RuntimeModeDependencyGraphWorker:
		if strings.TrimSpace(c.Bundle.ControlPlaneAddr) == "" {
			return fmt.Errorf(
				"invalid config: field %q is required when runtime.mode is %q",
				"bundle.control_plane_addr",
				c.Runtime.Mode,
			)
		}
		if (c.Runtime.Mode == RuntimeModeProxy || c.Runtime.Mode == RuntimeModeDependencyGraphWorker) &&
			c.Bundle.TLS.Mode != "mtls" {
			return fmt.Errorf(
				"invalid config: field %q must be %q when runtime.mode is %q",
				"bundle.tls.mode",
				"mtls",
				c.Runtime.Mode,
			)
		}
	}
	return nil
}
