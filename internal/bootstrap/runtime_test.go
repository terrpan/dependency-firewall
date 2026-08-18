package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/infra/upstream"
)

func TestProxyHealthChecker_UsesProxyResponse(t *testing.T) {
	t.Parallel()

	timestamp := time.Date(2026, time.May, 3, 14, 42, 24, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"status":"healthy",
			"proxy":{"status":"running","message":"proxy routes are served by this process","timestamp":"2026-05-03T14:42:24Z"},
			"bundle":{"status":"ready","message":"1 cached bundle","timestamp":"2026-05-03T14:42:24Z"}
		}`))
	}))
	defer server.Close()

	checker := &proxyHealthChecker{
		url:    server.URL,
		client: server.Client(),
	}

	status := checker.CheckStatus(context.Background())

	assert.Equal(t, "running", status.Status)
	assert.Equal(t, "proxy routes are served by this process; bundle=ready", status.Message)
	assert.Equal(t, timestamp, status.Timestamp)
}

func TestRegisterProxyRoutes_UsesBundleBackedTenantLookup(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerProxyRoutes(
		mux,
		&dependencies{},
		slog.Default(),
		BuildInfo{},
		staticBundleProvider{
			bundle: &domain.TenantBundle{
				Tenant:   domain.Tenant{ID: "tenant-123", Name: "Tenant 123"},
				TenantID: "tenant-123",
			},
		},
		false,
	)

	req := httptest.NewRequest(http.MethodGet, "http://tenant-123.localhost/v2/", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOCIClientOptions_ProxyModeUsesStrictResolver(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTestCertificate(t)
	cfg := &config.Config{
		Runtime: config.RuntimeConfig{Mode: config.RuntimeModeProxy},
		Bundle: config.BundleConfig{TLS: config.BundleTLSConfig{
			Mode:     "mtls",
			CertFile: certFile,
			KeyFile:  keyFile,
		}},
	}

	options, err := ociClientOptions(cfg)
	require.NoError(t, err)

	client := upstream.NewOCIClient(http.DefaultClient, options...)
	auth := &domain.UpstreamAuth{Type: domain.UpstreamAuthBearerToken, Secret: "plaintext-token"}
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("strict resolver should reject plaintext before sending request")
	}))
	defer registry.Close()

	_, err = client.FetchMetadata(
		context.Background(),
		domain.Upstream{BaseURL: registry.URL, Auth: auth},
		domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Namespace: "acme",
			Name:      "app",
			Version:   "1.0.0",
		},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hybrid secret envelope is required")
}

func TestOCIClientOptions_AllInOneModeUsesLegacyCompatibleResolver(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTestCertificate(t)
	cfg := &config.Config{
		Runtime: config.RuntimeConfig{Mode: config.RuntimeModeAllInOne},
		Bundle: config.BundleConfig{TLS: config.BundleTLSConfig{
			Mode:     "mtls",
			CertFile: certFile,
			KeyFile:  keyFile,
		}},
	}

	options, err := ociClientOptions(cfg)
	require.NoError(t, err)

	client := upstream.NewOCIClient(http.DefaultClient, options...)
	auth := &domain.UpstreamAuth{Type: domain.UpstreamAuthBearerToken, Secret: "plaintext-token"}
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer plaintext-token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	}))
	defer registry.Close()

	resp, err := client.FetchMetadata(
		context.Background(),
		domain.Upstream{BaseURL: registry.URL, Auth: auth},
		domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Namespace: "acme",
			Name:      "app",
			Version:   "1.0.0",
		},
	)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

type staticBundleProvider struct {
	bundle *domain.TenantBundle
}

func (p staticBundleProvider) GetTenantBundle(context.Context, string) (*domain.TenantBundle, error) {
	return p.bundle, nil
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-proxy"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	return certFile, keyFile
}
