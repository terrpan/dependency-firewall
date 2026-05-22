package bundlegrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/infra/secrets"
)

type bundleProviderFunc func(context.Context, string) (*domain.TenantBundle, error)

func (f bundleProviderFunc) GetTenantBundle(ctx context.Context, tenantID string) (*domain.TenantBundle, error) {
	return f(ctx, tenantID)
}

func TestBundleRoundTripPreservesTenantRuntime(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	bundle := &domain.TenantBundle{
		Tenant: domain.Tenant{
			ID:        "tenant-1",
			Name:      "Tenant One",
			CreatedAt: now.Add(-time.Hour),
			UpdatedAt: now,
		},
		TenantID:    "tenant-1",
		Revision:    "rev-1",
		GeneratedAt: now,
		Upstreams: []domain.Upstream{{
			ID:        "upstream-1",
			TenantID:  "tenant-1",
			Name:      "public-oci",
			Ecosystem: domain.EcosystemOCI,
			BaseURL:   "https://ghcr.io",
			CreatedAt: now.Add(-time.Hour),
			UpdatedAt: now,
		}},
	}

	response, err := bundleResponseForTest(bundle)
	require.NoError(t, err)

	restored, err := response.Bundle.ToDomain()
	require.NoError(t, err)
	assert.Equal(t, bundle.Tenant, restored.Tenant)
	assert.Equal(t, bundle.TenantID, restored.TenantID)
	require.Len(t, restored.Upstreams, 1)
	assert.Nil(t, restored.Upstreams[0].Auth)
}

func TestBundleToDomainFallsBackToLegacyTenantID(t *testing.T) {
	t.Parallel()

	bundle, err := (Bundle{TenantID: "tenant-1"}).ToDomain()
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", bundle.Tenant.ID)
	assert.Equal(t, "tenant-1", bundle.TenantID)
}

func TestBundleResponseEncryptsMetadataOnlyUpstreamAuth(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	server, err := NewServer(
		bundleProviderFunc(func(context.Context, string) (*domain.TenantBundle, error) { return nil, errors.New("unused") }),
		rewrapperFunc(func(_ context.Context, tenantID, upstreamID string, wrap port.UpstreamAuthSecretWrapper) ([]byte, error) {
			assert.Equal(t, "tenant-1", tenantID)
			assert.Equal(t, "upstream-1", upstreamID)
			return wrap([]byte("registry-token"))
		}),
	)
	require.NoError(t, err)
	bundle := &domain.TenantBundle{
		Tenant:      domain.Tenant{ID: "tenant-1"},
		TenantID:    "tenant-1",
		GeneratedAt: now,
		Upstreams: []domain.Upstream{{
			ID:        "upstream-1",
			TenantID:  "tenant-1",
			Name:      "private-oci",
			Ecosystem: domain.EcosystemOCI,
			BaseURL:   "https://ghcr.io",
			Auth: &domain.UpstreamAuth{
				Type:      domain.UpstreamAuthBearerToken,
				UpdatedAt: now,
			},
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
	assert.Empty(t, bundle.Upstreams[0].Auth.Secret)

	response, err := server.toBundleResponse(peerContext(&privateKey.PublicKey), bundle)
	require.NoError(t, err)
	require.Len(t, response.Bundle.Upstreams, 1)
	require.NotNil(t, response.Bundle.Upstreams[0].Auth)
	encrypted := response.Bundle.Upstreams[0].Auth.Secret
	assert.NotContains(t, encrypted, "registry-token")
	assert.True(t, secrets.IsHybridEnvelope([]byte(encrypted)))

	plaintext, err := secrets.DecryptWithPrivateKey(privateKey, []byte(encrypted))
	require.NoError(t, err)
	assert.Equal(t, "registry-token", string(plaintext))
}

func TestBundleResponseFailsClosedWithoutPeerCertificateForMetadataAuth(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	server, err := NewServer(
		bundleProviderFunc(func(context.Context, string) (*domain.TenantBundle, error) { return nil, errors.New("unused") }),
		rewrapperFunc(func(context.Context, string, string, port.UpstreamAuthSecretWrapper) ([]byte, error) {
			return []byte("should-not-run"), nil
		}),
	)
	require.NoError(t, err)
	bundle := &domain.TenantBundle{
		Tenant:      domain.Tenant{ID: "tenant-1"},
		TenantID:    "tenant-1",
		GeneratedAt: now,
		Upstreams: []domain.Upstream{{
			ID:        "upstream-1",
			TenantID:  "tenant-1",
			Ecosystem: domain.EcosystemOCI,
			Auth:      &domain.UpstreamAuth{Type: domain.UpstreamAuthBearerToken},
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}

	_, err = server.toBundleResponse(context.Background(), bundle)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "peer certificate")
}

func TestBundleResponseRejectsPlaintextSecretInDomain(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	server, err := NewServer(
		bundleProviderFunc(func(context.Context, string) (*domain.TenantBundle, error) { return nil, errors.New("unused") }),
		rewrapperFunc(func(context.Context, string, string, port.UpstreamAuthSecretWrapper) ([]byte, error) {
			return []byte("should-not-run"), nil
		}),
	)
	require.NoError(t, err)
	bundle := &domain.TenantBundle{
		Tenant:      domain.Tenant{ID: "tenant-1"},
		TenantID:    "tenant-1",
		GeneratedAt: now,
		Upstreams: []domain.Upstream{{
			ID:        "upstream-1",
			TenantID:  "tenant-1",
			Ecosystem: domain.EcosystemOCI,
			Auth: &domain.UpstreamAuth{
				Type:   domain.UpstreamAuthBearerToken,
				Secret: "registry-token",
			},
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}

	_, err = server.toBundleResponse(context.Background(), bundle)
	require.ErrorIs(t, err, domain.ErrUpstreamAuthInvalid)
}

func TestBundleResponsePropagatesRewrapperError(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	rewrapErr := errors.New("rewrap failed")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	server, err := NewServer(
		bundleProviderFunc(func(context.Context, string) (*domain.TenantBundle, error) { return nil, errors.New("unused") }),
		rewrapperFunc(func(context.Context, string, string, port.UpstreamAuthSecretWrapper) ([]byte, error) {
			return nil, rewrapErr
		}),
	)
	require.NoError(t, err)
	bundle := &domain.TenantBundle{
		Tenant:      domain.Tenant{ID: "tenant-1"},
		TenantID:    "tenant-1",
		GeneratedAt: now,
		Upstreams: []domain.Upstream{{
			ID:        "upstream-1",
			TenantID:  "tenant-1",
			Ecosystem: domain.EcosystemOCI,
			Auth:      &domain.UpstreamAuth{Type: domain.UpstreamAuthBearerToken},
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}

	_, err = server.toBundleResponse(peerContext(&privateKey.PublicKey), bundle)
	require.ErrorIs(t, err, rewrapErr)
}

func TestNewServerRequiresRewrapper(t *testing.T) {
	t.Parallel()

	_, err := NewServer(bundleProviderFunc(func(context.Context, string) (*domain.TenantBundle, error) {
		return nil, errors.New("unused")
	}), nil)
	require.Error(t, err)
}

type rewrapperFunc func(context.Context, string, string, port.UpstreamAuthSecretWrapper) ([]byte, error)

func (f rewrapperFunc) RewrapUpstreamAuthSecret(ctx context.Context, tenantID, upstreamID string, wrap port.UpstreamAuthSecretWrapper) ([]byte, error) {
	return f(ctx, tenantID, upstreamID, wrap)
}

func peerContext(publicKey any) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{
					PublicKey: publicKey,
				}},
			},
		},
	})
}

func bundleResponseForTest(bundle *domain.TenantBundle) (*GetTenantBundleResponse, error) {
	server, err := NewServer(
		bundleProviderFunc(func(context.Context, string) (*domain.TenantBundle, error) { return nil, errors.New("unused") }),
		rewrapperFunc(func(context.Context, string, string, port.UpstreamAuthSecretWrapper) ([]byte, error) {
			return []byte("unused"), nil
		}),
	)
	if err != nil {
		return nil, err
	}
	return server.toBundleResponse(context.Background(), bundle)
}
