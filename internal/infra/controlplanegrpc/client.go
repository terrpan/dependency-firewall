package controlplanegrpc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

// NewClientConn creates a control-plane gRPC client connection using the shared
// JSON codec and telemetry dial options.
func NewClientConn(address string, configs ...config.BundleTLSConfig) (*grpc.ClientConn, error) {
	options, err := DialOptions(configs...)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(address, options...)
}

// DialOptions returns the shared client dial options for control-plane gRPC
// traffic.
func DialOptions(configs ...config.BundleTLSConfig) ([]grpc.DialOption, error) {
	transport, err := clientTransportCredentials(bundleTLSConfig(configs...))
	if err != nil {
		return nil, err
	}
	return append([]grpc.DialOption{
		grpc.WithTransportCredentials(transport),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	}, telemetry.ClientDialOptions()...), nil
}

// ServerOptions returns the shared server options for control-plane gRPC
// traffic.
func ServerOptions(configs ...config.BundleTLSConfig) ([]grpc.ServerOption, error) {
	transport, err := serverTransportCredentials(bundleTLSConfig(configs...))
	if err != nil {
		return nil, err
	}
	options := []grpc.ServerOption{grpc.ForceServerCodec(jsonCodec{})}
	if transport != nil {
		options = append(options, grpc.Creds(transport))
	}
	return options, nil
}

func bundleTLSConfig(configs ...config.BundleTLSConfig) config.BundleTLSConfig {
	if len(configs) == 0 {
		return config.BundleTLSConfig{Mode: "insecure"}
	}
	return configs[0]
}

func clientTransportCredentials(cfg config.BundleTLSConfig) (credentials.TransportCredentials, error) {
	if cfg.Mode != "mtls" {
		return insecure.NewCredentials(), nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading grpc client certificate: %w", err)
	}
	roots, err := certPoolFromFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   cfg.ServerNameOverride,
	}), nil
}

func serverTransportCredentials(cfg config.BundleTLSConfig) (credentials.TransportCredentials, error) {
	if cfg.Mode != "mtls" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading grpc server certificate: %w", err)
	}
	clientCAs, err := certPoolFromFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}), nil
}

func certPoolFromFile(path string) (*x509.CertPool, error) {
	//nolint:gosec // path is an operator-supplied CA file from static config, not request input
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading grpc ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("parsing grpc ca file: no certificates found")
	}
	return pool, nil
}

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}
