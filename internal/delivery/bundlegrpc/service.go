package bundlegrpc

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/infra/secrets"
	bundlewire "github.com/danielterry/dependency-firewall/internal/wire/bundlegrpc"
)

const serviceName = bundlewire.ServiceName

type GetTenantBundleRequest = bundlewire.GetTenantBundleRequest
type GetTenantBundleResponse = bundlewire.GetTenantBundleResponse
type Bundle = bundlewire.Bundle
type BundleTenant = bundlewire.BundleTenant
type BundlePolicy = bundlewire.BundlePolicy
type BundleUpstream = bundlewire.BundleUpstream
type BundleUpstreamAuth = bundlewire.BundleUpstreamAuth

type bundleService interface {
	GetTenantBundle(context.Context, *GetTenantBundleRequest) (*GetTenantBundleResponse, error)
}

// Server serves tenant bundles over gRPC.
type Server struct {
	provider        port.TenantBundleProvider
	secretRewrapper port.UpstreamAuthSecretRewrapper
}

// NewServer creates a new Server.
func NewServer(provider port.TenantBundleProvider, secretRewrapper port.UpstreamAuthSecretRewrapper) (*Server, error) {
	if provider == nil {
		return nil, fmt.Errorf("bundle provider is required")
	}
	if secretRewrapper == nil {
		return nil, fmt.Errorf("upstream auth secret rewrapper is required")
	}
	return &Server{provider: provider, secretRewrapper: secretRewrapper}, nil
}

// TenantIDFromRequest returns the tenant id carried by bundle gRPC requests.
func TenantIDFromRequest(req any) string {
	return bundlewire.TenantIDFromRequest(req)
}

// Register registers the bundle service on the given gRPC registrar.
func (s *Server) Register(registrar grpc.ServiceRegistrar) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*bundleService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "GetTenantBundle",
				Handler:    s.getTenantBundleHandler,
			},
		},
	}, s)
}

// GetTenantBundle returns the current bundle for a tenant.
func (s *Server) GetTenantBundle(ctx context.Context, req *GetTenantBundleRequest) (*GetTenantBundleResponse, error) {
	if req == nil || req.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	bundle, err := s.provider.GetTenantBundle(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}

	response, err := s.toBundleResponse(ctx, bundle)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Server) getTenantBundleHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	req := &GetTenantBundleRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}

	if interceptor == nil {
		return srv.(bundleService).GetTenantBundle(ctx, req)
	}

	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/" + serviceName + "/GetTenantBundle",
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(bundleService).GetTenantBundle(ctx, req.(*GetTenantBundleRequest))
	}
	return interceptor(ctx, req, info, handler)
}

// GetTenantBundle invokes the remote bundle service using the given client connection.
func GetTenantBundle(ctx context.Context, conn grpc.ClientConnInterface, tenantID string) (*domain.TenantBundle, error) {
	response, err := bundlewire.FetchTenantBundleResponse(ctx, conn, tenantID)
	if err != nil {
		return nil, err
	}
	return response.Bundle.ToDomain()
}

func (s *Server) toBundleResponse(ctx context.Context, bundle *domain.TenantBundle) (*GetTenantBundleResponse, error) {
	tenant := bundle.Tenant
	if tenant.ID == "" {
		tenant.ID = bundle.TenantID
	}

	response := &GetTenantBundleResponse{
		Bundle: Bundle{
			Tenant: BundleTenant{
				ID:        tenant.ID,
				Name:      tenant.Name,
				CreatedAt: tenant.CreatedAt.UTC().Format(bundlewire.TimeLayout),
				UpdatedAt: tenant.UpdatedAt.UTC().Format(bundlewire.TimeLayout),
			},
			TenantID:    tenant.ID,
			Revision:    bundle.Revision,
			GeneratedAt: bundle.GeneratedAt.UTC().Format(bundlewire.TimeLayout),
			Policies:    make([]BundlePolicy, 0, len(bundle.Policies)),
			Upstreams:   make([]BundleUpstream, 0, len(bundle.Upstreams)),
		},
	}

	for i := range bundle.Policies {
		config, err := json.Marshal(bundle.Policies[i].Config)
		if err != nil {
			return nil, fmt.Errorf("marshalling bundle policy config: %w", err)
		}

		response.Bundle.Policies = append(response.Bundle.Policies, BundlePolicy{
			ID:            bundle.Policies[i].ID,
			TenantID:      bundle.Policies[i].TenantID,
			UpstreamID:    bundle.Policies[i].UpstreamID,
			Name:          bundle.Policies[i].Name,
			Type:          bundle.Policies[i].Type,
			Action:        bundle.Policies[i].Action,
			SchemaVersion: bundle.Policies[i].SchemaVersion,
			Config:        config,
			Target:        bundle.Policies[i].Target,
			Priority:      bundle.Policies[i].Priority,
			Enabled:       bundle.Policies[i].Enabled,
			Version:       bundle.Policies[i].Version,
			CreatedAt:     bundle.Policies[i].CreatedAt.UTC().Format(bundlewire.TimeLayout),
			UpdatedAt:     bundle.Policies[i].UpdatedAt.UTC().Format(bundlewire.TimeLayout),
		})
	}

	var peerPublicKey crypto.PublicKey
	for i := range bundle.Upstreams {
		effectiveCapabilities := bundle.Upstreams[i].EffectiveCapabilities()
		var auth *BundleUpstreamAuth
		if bundle.Upstreams[i].Auth != nil {
			secret := ""
			if bundle.Upstreams[i].Auth.Configured() {
				// SECURITY: bundle domain memory must not carry plaintext upstream
				// auth secrets; decrypt and re-encrypt in one rewrapper operation.
				if bundle.Upstreams[i].Auth.Secret != "" {
					return nil, fmt.Errorf("%w: bundle upstream auth secret must not be present in domain bundle", domain.ErrUpstreamAuthInvalid)
				}
				if peerPublicKey == nil {
					var err error
					peerPublicKey, err = peerCertificatePublicKey(ctx)
					if err != nil {
						return nil, err
					}
				}
				encrypted, err := s.encryptUpstreamAuthSecret(
					ctx,
					bundle.TenantID,
					bundle.Upstreams[i].ID,
					peerPublicKey,
				)
				if err != nil {
					return nil, err
				}
				secret = string(encrypted)
			}
			auth = &BundleUpstreamAuth{
				Type:     bundle.Upstreams[i].Auth.Type,
				Username: bundle.Upstreams[i].Auth.Username,
				Secret:   secret,
			}
			if !bundle.Upstreams[i].Auth.UpdatedAt.IsZero() {
				auth.UpdatedAt = bundle.Upstreams[i].Auth.UpdatedAt.UTC().Format(bundlewire.TimeLayout)
			}
		}
		response.Bundle.Upstreams = append(response.Bundle.Upstreams, BundleUpstream{
			ID:           bundle.Upstreams[i].ID,
			TenantID:     bundle.Upstreams[i].TenantID,
			Name:         bundle.Upstreams[i].Name,
			Ecosystem:    bundle.Upstreams[i].Ecosystem,
			BaseURL:      bundle.Upstreams[i].BaseURL,
			Capabilities: domain.UpstreamCapabilityStrings(effectiveCapabilities),
			Auth:         auth,
			CreatedAt:    bundle.Upstreams[i].CreatedAt.UTC().Format(bundlewire.TimeLayout),
			UpdatedAt:    bundle.Upstreams[i].UpdatedAt.UTC().Format(bundlewire.TimeLayout),
		})
	}

	return response, nil
}

func (s *Server) encryptUpstreamAuthSecret(ctx context.Context, tenantID, upstreamID string, publicKey crypto.PublicKey) ([]byte, error) {
	return s.secretRewrapper.RewrapUpstreamAuthSecret(ctx, tenantID, upstreamID, func(plaintext []byte) ([]byte, error) {
		return secrets.EncryptForPublicKey(publicKey, plaintext)
	})
}

func peerCertificatePublicKey(ctx context.Context) (crypto.PublicKey, error) {
	cert, err := peerCertificate(ctx)
	if err != nil {
		return nil, err
	}
	if cert.PublicKey == nil {
		return nil, fmt.Errorf("peer certificate public key is missing")
	}
	return cert.PublicKey, nil
}

func peerCertificate(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("peer certificate is required for encrypted upstream auth")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, fmt.Errorf("peer certificate is required for encrypted upstream auth")
	}
	return tlsInfo.State.PeerCertificates[0], nil
}
