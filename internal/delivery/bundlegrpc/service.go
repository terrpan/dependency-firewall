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
type BundleCredential = bundlewire.BundleCredential

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
func GetTenantBundle(
	ctx context.Context,
	conn grpc.ClientConnInterface,
	tenantID string,
) (*domain.TenantBundle, error) {
	response, err := bundlewire.FetchTenantBundleResponse(ctx, conn, tenantID)
	if err != nil {
		return nil, err
	}
	return response.Bundle.ToDomain()
}

func (s *Server) toBundleResponse(ctx context.Context, bundle *domain.TenantBundle) (*GetTenantBundleResponse, error) {
	response := newBundleResponse(bundle)
	for i := range bundle.Credentials {
		response.Bundle.Credentials = append(response.Bundle.Credentials, toBundleCredential(bundle.Credentials[i]))
	}
	for i := range bundle.Policies {
		policy, err := toBundlePolicy(bundle.Policies[i])
		if err != nil {
			return nil, err
		}
		response.Bundle.Policies = append(response.Bundle.Policies, policy)
	}

	var peerPublicKey crypto.PublicKey
	for i := range bundle.Upstreams {
		upstream, err := s.toBundleUpstream(ctx, bundle.TenantID, bundle.Upstreams[i], &peerPublicKey)
		if err != nil {
			return nil, err
		}
		response.Bundle.Upstreams = append(response.Bundle.Upstreams, upstream)
	}
	return response, nil
}

func newBundleResponse(bundle *domain.TenantBundle) *GetTenantBundleResponse {
	tenant := bundle.Tenant
	if tenant.ID == "" {
		tenant.ID = bundle.TenantID
	}
	return &GetTenantBundleResponse{
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
			Credentials: make([]BundleCredential, 0, len(bundle.Credentials)),
		},
	}
}

func toBundleCredential(credential domain.DataPlaneCredentialVerifier) BundleCredential {
	return BundleCredential{
		ID:             credential.ID,
		TenantID:       credential.TenantID,
		OrganizationID: credential.OrganizationID,
		TeamID:         credential.TeamID,
		SecretDigest:   credential.SecretDigest,
		ExpiresAt:      credential.ExpiresAt,
		RevokedAt:      credential.RevokedAt,
	}
}

func toBundlePolicy(policy domain.Policy) (BundlePolicy, error) {
	policy.NormalizeScope()
	config, err := json.Marshal(policy.Config)
	if err != nil {
		return BundlePolicy{}, fmt.Errorf("marshalling bundle policy config: %w", err)
	}
	return BundlePolicy{
		ID:             policy.ID,
		TenantID:       policy.TenantID,
		OrganizationID: policy.OrganizationID,
		ScopeKind:      policy.ScopeKind,
		WaiverMode:     policy.WaiverMode,
		UpstreamID:     policy.UpstreamID,
		Name:           policy.Name,
		Type:           policy.Type,
		Action:         policy.Action,
		SchemaVersion:  policy.SchemaVersion,
		Config:         config,
		Target:         policy.Target,
		Priority:       policy.Priority,
		Enabled:        policy.Enabled,
		Version:        policy.Version,
		CreatedAt:      policy.CreatedAt.UTC().Format(bundlewire.TimeLayout),
		UpdatedAt:      policy.UpdatedAt.UTC().Format(bundlewire.TimeLayout),
	}, nil
}

func (s *Server) toBundleUpstream(
	ctx context.Context,
	tenantID string,
	upstream domain.Upstream,
	peerPublicKey *crypto.PublicKey,
) (BundleUpstream, error) {
	upstream.NormalizeScope()
	auth, err := s.toBundleUpstreamAuth(ctx, tenantID, upstream, peerPublicKey)
	if err != nil {
		return BundleUpstream{}, err
	}
	return BundleUpstream{
		ID:             upstream.ID,
		TenantID:       upstream.TenantID,
		OrganizationID: upstream.OrganizationID,
		TeamID:         upstream.TeamID,
		ScopeKind:      upstream.ScopeKind,
		Name:           upstream.Name,
		Ecosystem:      upstream.Ecosystem,
		BaseURL:        upstream.BaseURL,
		Capabilities:   domain.UpstreamCapabilityStrings(upstream.EffectiveCapabilities()),
		Auth:           auth,
		CreatedAt:      upstream.CreatedAt.UTC().Format(bundlewire.TimeLayout),
		UpdatedAt:      upstream.UpdatedAt.UTC().Format(bundlewire.TimeLayout),
	}, nil
}

func (s *Server) toBundleUpstreamAuth(
	ctx context.Context,
	tenantID string,
	upstream domain.Upstream,
	peerPublicKey *crypto.PublicKey,
) (*BundleUpstreamAuth, error) {
	if upstream.Auth == nil {
		return nil, nil
	}
	secret, err := s.bundleUpstreamAuthSecret(ctx, tenantID, upstream, peerPublicKey)
	if err != nil {
		return nil, err
	}
	auth := &BundleUpstreamAuth{
		Type:     upstream.Auth.Type,
		Username: upstream.Auth.Username,
		Secret:   secret,
	}
	if !upstream.Auth.UpdatedAt.IsZero() {
		auth.UpdatedAt = upstream.Auth.UpdatedAt.UTC().Format(bundlewire.TimeLayout)
	}
	return auth, nil
}

func (s *Server) bundleUpstreamAuthSecret(
	ctx context.Context,
	tenantID string,
	upstream domain.Upstream,
	peerPublicKey *crypto.PublicKey,
) (string, error) {
	if !upstream.Auth.Configured() {
		return "", nil
	}
	// SECURITY: bundle domain memory must not carry plaintext upstream
	// auth secrets; decrypt and re-encrypt in one rewrapper operation.
	if upstream.Auth.Secret != "" {
		return "", fmt.Errorf(
			"%w: bundle upstream auth secret must not be present in domain bundle",
			domain.ErrUpstreamAuthInvalid,
		)
	}
	if *peerPublicKey == nil {
		publicKey, err := peerCertificatePublicKey(ctx)
		if err != nil {
			return "", err
		}
		*peerPublicKey = publicKey
	}
	encrypted, err := s.encryptUpstreamAuthSecret(ctx, tenantID, upstream.ID, *peerPublicKey)
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}

func (s *Server) encryptUpstreamAuthSecret(
	ctx context.Context,
	tenantID, upstreamID string,
	publicKey crypto.PublicKey,
) ([]byte, error) {
	return s.secretRewrapper.RewrapUpstreamAuthSecret(
		ctx,
		tenantID,
		upstreamID,
		func(plaintext []byte) ([]byte, error) {
			return secrets.EncryptForPublicKey(publicKey, plaintext)
		},
	)
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
