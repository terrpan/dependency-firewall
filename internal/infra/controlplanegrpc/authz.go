package controlplanegrpc

import (
	"context"
	"crypto/x509"
	"log/slog"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/danielterry/dependency-firewall/internal/config"
)

// TenantIDExtractor returns the tenant id carried by a decoded control-plane RPC request.
type TenantIDExtractor func(any) string

// TenantAuthorizationDeniedEvent describes a rejected tenant-scoped control-plane RPC.
type TenantAuthorizationDeniedEvent struct {
	TenantID          string
	ClientIdentities  []string
	FullMethod        string
	Reason            string
	PermissionMessage string
}

// TenantAuthorizationDeniedRecorder records a rejected tenant-scoped control-plane RPC.
type TenantAuthorizationDeniedRecorder func(context.Context, TenantAuthorizationDeniedEvent) error

type tenantAuthorizationConfig struct {
	logger         *slog.Logger
	deniedRecorder TenantAuthorizationDeniedRecorder
}

// TenantAuthorizationOption customizes the tenant authorization interceptor.
type TenantAuthorizationOption func(*tenantAuthorizationConfig)

// WithTenantAuthorizationLogger logs authorization denials from the control-plane gRPC boundary.
func WithTenantAuthorizationLogger(logger *slog.Logger) TenantAuthorizationOption {
	return func(cfg *tenantAuthorizationConfig) {
		cfg.logger = logger
	}
}

// WithTenantAuthorizationDeniedRecorder records authorization denials through an audit sink.
func WithTenantAuthorizationDeniedRecorder(recorder TenantAuthorizationDeniedRecorder) TenantAuthorizationOption {
	return func(cfg *tenantAuthorizationConfig) {
		cfg.deniedRecorder = recorder
	}
}

// TenantAuthorizationInterceptor authorizes mTLS client identities for tenant-scoped control-plane RPCs.
func TenantAuthorizationInterceptor(
	clients []config.BundleTLSAuthorizedClient,
	extractTenantID TenantIDExtractor,
	options ...TenantAuthorizationOption,
) grpc.UnaryServerInterceptor {
	authorizer := newTenantAuthorizer(clients)
	cfg := tenantAuthorizationConfig{}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		fullMethod := ""
		if info != nil {
			fullMethod = info.FullMethod
		}
		if err := cfg.authorize(ctx, req, fullMethod, authorizer, extractTenantID); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// TenantAuthorizationStreamInterceptor authorizes mTLS client identities for
// tenant-scoped streaming control-plane RPCs after decoding the first request.
func TenantAuthorizationStreamInterceptor(
	clients []config.BundleTLSAuthorizedClient,
	extractTenantID TenantIDExtractor,
	options ...TenantAuthorizationOption,
) grpc.StreamServerInterceptor {
	authorizer := newTenantAuthorizer(clients)
	cfg := tenantAuthorizationConfig{}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		fullMethod := ""
		if info != nil {
			fullMethod = info.FullMethod
		}
		authorizingStream := &tenantAuthorizingServerStream{
			ServerStream: stream,
			authorize: func(req any) error {
				return cfg.authorize(stream.Context(), req, fullMethod, authorizer, extractTenantID)
			},
		}
		return handler(srv, authorizingStream)
	}
}

func (cfg tenantAuthorizationConfig) authorize(
	ctx context.Context,
	req any,
	fullMethod string,
	authorizer tenantAuthorizer,
	extractTenantID TenantIDExtractor,
) error {
	if extractTenantID == nil {
		_, err := cfg.deny(ctx, TenantAuthorizationDeniedEvent{
			FullMethod:        fullMethod,
			Reason:            "tenant_id_extractor_missing",
			PermissionMessage: "tenant id extractor is not configured",
		}, codes.Internal)
		return err
	}
	tenantID := strings.TrimSpace(extractTenantID(req))
	if tenantID == "" {
		_, err := cfg.deny(ctx, TenantAuthorizationDeniedEvent{
			FullMethod:        fullMethod,
			Reason:            "tenant_id_missing",
			PermissionMessage: "tenant_id is required",
		}, codes.InvalidArgument)
		return err
	}
	identities := peerCertificateIdentities(ctx)
	if len(identities) == 0 {
		_, err := cfg.deny(ctx, TenantAuthorizationDeniedEvent{
			TenantID:          tenantID,
			FullMethod:        fullMethod,
			Reason:            "client_certificate_identity_missing",
			PermissionMessage: "client certificate identity is required",
		}, codes.Unauthenticated)
		return err
	}
	if authorizer.authorized(identities, tenantID) {
		return nil
	}
	_, err := cfg.deny(ctx, TenantAuthorizationDeniedEvent{
		TenantID:          tenantID,
		ClientIdentities:  identities,
		FullMethod:        fullMethod,
		Reason:            "client_certificate_not_authorized_for_tenant",
		PermissionMessage: "client certificate is not authorized for tenant " + strconv.Quote(tenantID),
	}, codes.PermissionDenied)
	return err
}

type tenantAuthorizingServerStream struct {
	grpc.ServerStream
	authorize  func(any) error
	authorized bool
}

func (s *tenantAuthorizingServerStream) RecvMsg(message any) error {
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	if s.authorized {
		return nil
	}
	if err := s.authorize(message); err != nil {
		return err
	}
	s.authorized = true
	return nil
}

func (cfg tenantAuthorizationConfig) deny(
	ctx context.Context,
	event TenantAuthorizationDeniedEvent,
	code codes.Code,
) (any, error) {
	event.TenantID = strings.TrimSpace(event.TenantID)
	event.FullMethod = strings.TrimSpace(event.FullMethod)
	event.Reason = strings.TrimSpace(event.Reason)
	event.PermissionMessage = strings.TrimSpace(event.PermissionMessage)
	event.ClientIdentities = append([]string(nil), event.ClientIdentities...)
	if event.PermissionMessage == "" {
		event.PermissionMessage = "control-plane grpc request denied"
	}

	if cfg.logger != nil {
		cfg.logger.WarnContext(ctx, "control-plane grpc request denied",
			"tenant_id", event.TenantID,
			"grpc_method", event.FullMethod,
			"reason", event.Reason,
			"client_identities", event.ClientIdentities,
		)
	}
	if cfg.deniedRecorder != nil {
		if err := cfg.deniedRecorder(ctx, event); err != nil && cfg.logger != nil {
			cfg.logger.ErrorContext(ctx, "recording control-plane grpc authorization denial",
				"error", err,
				"tenant_id", event.TenantID,
				"grpc_method", event.FullMethod,
				"reason", event.Reason,
			)
		}
	}

	return nil, status.Error(code, event.PermissionMessage)
}

type tenantAuthorizer map[string]map[string]struct{}

func newTenantAuthorizer(clients []config.BundleTLSAuthorizedClient) tenantAuthorizer {
	result := make(tenantAuthorizer, len(clients))
	for _, client := range clients {
		identity := strings.TrimSpace(client.Identity)
		if identity == "" {
			continue
		}
		tenants := result[identity]
		if tenants == nil {
			tenants = make(map[string]struct{}, len(client.TenantIDs))
			result[identity] = tenants
		}
		for _, tenantID := range client.TenantIDs {
			tenantID = strings.TrimSpace(tenantID)
			if tenantID != "" {
				tenants[tenantID] = struct{}{}
			}
		}
	}
	return result
}

func (a tenantAuthorizer) authorized(identities []string, tenantID string) bool {
	for _, identity := range identities {
		tenants, ok := a[identity]
		if !ok {
			continue
		}
		if _, ok := tenants["*"]; ok {
			return true
		}
		if _, ok := tenants[tenantID]; ok {
			return true
		}
	}
	return false
}

func peerCertificateIdentities(ctx context.Context) []string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil
	}
	return certificateIdentities(tlsInfo.State.PeerCertificates[0])
}

func certificateIdentities(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	identities := make([]string, 0, len(cert.URIs)+len(cert.DNSNames)+len(cert.EmailAddresses)+1)
	for _, uri := range cert.URIs {
		identities = append(identities, uri.String())
	}
	identities = append(identities, cert.DNSNames...)
	identities = append(identities, cert.EmailAddresses...)
	if cert.Subject.CommonName != "" {
		identities = append(identities, cert.Subject.CommonName)
	}
	return identities
}
