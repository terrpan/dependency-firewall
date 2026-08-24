package workloadidentity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// RuntimeCredentials is in-memory proxy identity material. PrivateKey is never serialized by this package.
type RuntimeCredentials struct {
	TenantID       string
	InstallationID string
	IdentityID     string
	GRPCAddress    string
	GRPCServerName string
	TLSConfig      *tls.Config
	PrivateKey     any
}

// RuntimeCredentialProvider acquires credentials for one proxy process lifetime.
type RuntimeCredentialProvider interface {
	Acquire(context.Context) (*RuntimeCredentials, error)
}

// FileProviderConfig describes existing manually provisioned proxy credentials.
type FileProviderConfig struct {
	CAFile, CertificateFile, PrivateKeyFile, ServerName, GRPCAddress string
}

// FileProvider preserves the existing mounted-file deployment behind the runtime provider boundary.
type FileProvider struct{ config FileProviderConfig }

// NewFileProvider creates a provider for existing mounted credentials.
func NewFileProvider(cfg FileProviderConfig) *FileProvider { return &FileProvider{config: cfg} }

// Acquire loads manual credentials into the common in-memory runtime form.
func (p *FileProvider) Acquire(context.Context) (*RuntimeCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(p.config.CertificateFile, p.config.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading proxy client certificate: %w", err)
	}
	rootsPEM, err := readBoundedFile(p.config.CAFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading proxy server trust bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return nil, fmt.Errorf("proxy server trust bundle contains no certificates")
	}
	return &RuntimeCredentials{
		GRPCAddress:    p.config.GRPCAddress,
		GRPCServerName: p.config.ServerName,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
			ServerName:   p.config.ServerName,
		},
		PrivateKey: certificate.PrivateKey,
	}, nil
}

// EnrollmentProviderConfig configures the enrollment HTTPS client.
type EnrollmentProviderConfig struct {
	PublicAPIURL     string
	AdditionalCAFile string
	ProposedName     string
	HTTPClient       *http.Client
	Logger           *slog.Logger
}

// EnrollmentProvider creates a process-local key and enrolls it without writing credential files.
type EnrollmentProvider struct {
	config    EnrollmentProviderConfig
	clientErr error
}

// NewEnrollmentProvider creates an automatic HTTPS enrollment provider.
func NewEnrollmentProvider(cfg EnrollmentProviderConfig) *EnrollmentProvider {
	if cfg.HTTPClient == nil {
		client, err := newEnrollmentHTTPClient(cfg.AdditionalCAFile)
		if err != nil {
			return &EnrollmentProvider{config: cfg, clientErr: err}
		}
		cfg.HTTPClient = client
	}
	return &EnrollmentProvider{config: cfg}
}

type startRequest struct {
	CSRPEM       string `json:"csr_pem"`
	ProposedName string `json:"proposed_name,omitempty"`
}

type startResponse struct {
	DeviceCredential    string `json:"device_credential"`
	UserCode            string `json:"user_code"`
	VerificationURI     string `json:"verification_uri"`
	PollIntervalSeconds int64  `json:"poll_interval_seconds"`
}

type tokenResponse struct {
	Error                     string `json:"error"`
	TenantID                  string `json:"tenant_id"`
	InstallationID            string `json:"installation_id"`
	IdentityID                string `json:"identity_id"`
	ClientCertificateChainPEM string `json:"client_certificate_chain_pem"`
	ServerTrustBundlePEM      string `json:"server_trust_bundle_pem"`
	GRPCAddress               string `json:"grpc_address"`
	GRPCServerName            string `json:"grpc_server_name"`
}

// Acquire generates a process-local key and completes the one-time enrollment state machine.
//
//nolint:gocyclo,funlen // response handling intentionally maps every protocol state explicitly.
func (p *EnrollmentProvider) Acquire(ctx context.Context) (*RuntimeCredentials, error) {
	if p.clientErr != nil {
		return nil, fmt.Errorf("configuring enrollment HTTPS trust: %w", p.clientErr)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating process-local proxy key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating proxy enrollment CSR: %w", err)
	}
	requestBody, err := json.Marshal(startRequest{
		CSRPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		ProposedName: p.config.ProposedName,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding proxy enrollment request: %w", err)
	}
	endpoint := strings.TrimRight(p.config.PublicAPIURL, "/") + "/api/v1/proxy-enrollments"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("creating proxy enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("starting proxy enrollment: %w", err)
	}
	started := startResponse{}
	if err := decodeJSONResponse(resp, http.StatusCreated, &started); err != nil {
		return nil, fmt.Errorf("starting proxy enrollment: %w", err)
	}
	if started.DeviceCredential == "" || started.UserCode == "" || started.VerificationURI == "" {
		return nil, fmt.Errorf("starting proxy enrollment: incomplete server response")
	}
	if p.config.Logger != nil {
		p.config.Logger.Info("proxy activation required",
			"verification_uri", started.VerificationURI,
			"user_code", started.UserCode,
		)
	}
	interval := time.Duration(started.PollIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		result, status, err := p.poll(ctx, started.DeviceCredential)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusAccepted:
			continue
		case http.StatusTooManyRequests:
			interval += 5 * time.Second
			continue
		case http.StatusOK:
			return validateEnrollmentResult(result, privateKey)
		case http.StatusForbidden:
			return nil, fmt.Errorf("proxy enrollment denied")
		case http.StatusGone:
			return nil, fmt.Errorf("proxy enrollment expired or was already consumed")
		default:
			return nil, fmt.Errorf("proxy enrollment poll returned HTTP %d", status)
		}
	}
}

func newEnrollmentHTTPClient(additionalCAFile string) (*http.Client, error) {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport has an unexpected type")
	}
	transport := baseTransport.Clone()
	if strings.TrimSpace(additionalCAFile) == "" {
		return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	pemBytes, err := readBoundedFile(additionalCAFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading additional CA bundle: %w", err)
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("parsing additional CA bundle: no certificates found")
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func (p *EnrollmentProvider) poll(ctx context.Context, credential string) (tokenResponse, int, error) {
	endpoint := strings.TrimRight(p.config.PublicAPIURL, "/") + "/api/v1/proxy-enrollments/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return tokenResponse{}, 0, fmt.Errorf("creating proxy enrollment poll: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := p.config.HTTPClient.Do(req)
	if err != nil {
		return tokenResponse{}, 0, fmt.Errorf("polling proxy enrollment: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	contents, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return tokenResponse{}, 0, fmt.Errorf("reading proxy enrollment poll: %w", err)
	}
	result := tokenResponse{}
	if len(contents) > 0 && json.Unmarshal(contents, &result) != nil {
		return tokenResponse{}, 0, fmt.Errorf("decoding proxy enrollment poll response")
	}
	return result, resp.StatusCode, nil
}

func validateEnrollmentResult(result tokenResponse, privateKey *ecdsa.PrivateKey) (*RuntimeCredentials, error) {
	certificateDER, err := parseCertificateChainPEM([]byte(result.ClientCertificateChainPEM))
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certificateDER[0])
	if err != nil {
		return nil, fmt.Errorf("parsing enrolled proxy certificate: %w", err)
	}
	leafPublicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKeysEqual(leafPublicKey, &privateKey.PublicKey) {
		return nil, fmt.Errorf("enrolled proxy certificate does not match process-local key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(result.ServerTrustBundlePEM)) {
		return nil, fmt.Errorf("enrollment response contains no gRPC server trust certificates")
	}
	if result.TenantID == "" || result.InstallationID == "" || result.IdentityID == "" || result.GRPCAddress == "" ||
		result.GRPCServerName == "" {
		return nil, fmt.Errorf("enrollment response is missing runtime identity metadata")
	}
	certificate := tls.Certificate{Certificate: certificateDER, PrivateKey: privateKey, Leaf: leaf}
	return &RuntimeCredentials{
		TenantID:       result.TenantID,
		InstallationID: result.InstallationID,
		IdentityID:     result.IdentityID,
		GRPCAddress:    result.GRPCAddress,
		GRPCServerName: result.GRPCServerName,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
			ServerName:   result.GRPCServerName,
		},
		PrivateKey: privateKey,
	}, nil
}

func parseCertificateChainPEM(contents []byte) ([][]byte, error) {
	var result [][]byte
	for len(bytes.TrimSpace(contents)) > 0 {
		block, rest := pem.Decode(contents)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("enrollment response contains an invalid certificate chain")
		}
		result = append(result, append([]byte(nil), block.Bytes...))
		contents = rest
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("enrollment response contains no client certificate")
	}
	return result, nil
}

func decodeJSONResponse(response *http.Response, expectedStatus int, target any) error {
	defer func() { _ = response.Body.Close() }()
	contents, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	if err := json.Unmarshal(contents, target); err != nil {
		return fmt.Errorf("decoding JSON response: %w", err)
	}
	return nil
}
