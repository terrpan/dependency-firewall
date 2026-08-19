package controlplanegrpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/config"
)

func TestTenantAuthorizer(t *testing.T) {
	t.Parallel()

	authorizer := newTenantAuthorizer([]config.BundleTLSAuthorizedClient{
		{Identity: "spiffe://dependency-firewall/proxy/a", TenantIDs: []string{"tenant-a"}},
		{Identity: "spiffe://dependency-firewall/proxy/admin", TenantIDs: []string{"*"}},
	})

	assert.True(t, authorizer.authorized([]string{"spiffe://dependency-firewall/proxy/a"}, "tenant-a"))
	assert.False(t, authorizer.authorized([]string{"spiffe://dependency-firewall/proxy/a"}, "tenant-b"))
	assert.True(t, authorizer.authorized([]string{"spiffe://dependency-firewall/proxy/admin"}, "tenant-b"))
	assert.False(t, authorizer.authorized([]string{"spiffe://dependency-firewall/proxy/unknown"}, "tenant-a"))
}

func TestTenantAuthorizationInterceptor_RecordsDeniedRequest(t *testing.T) {
	t.Parallel()

	var recorded TenantAuthorizationDeniedEvent
	interceptor := TenantAuthorizationInterceptor(
		[]config.BundleTLSAuthorizedClient{
			{Identity: "proxy-a.firewall.local", TenantIDs: []string{"tenant-a"}},
		},
		func(any) string { return "tenant-b" },
		WithTenantAuthorizationDeniedRecorder(func(_ context.Context, event TenantAuthorizationDeniedEvent) error {
			recorded = event
			return nil
		}),
	)
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tlsConnectionState(&x509.Certificate{DNSNames: []string{"proxy-a.firewall.local"}}),
		},
	})

	_, err := interceptor(
		ctx,
		struct{}{},
		&grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"},
		func(context.Context, any) (any, error) {
			t.Fatal("handler should not be called")
			return nil, nil
		},
	)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, "tenant-b", recorded.TenantID)
	assert.Equal(t, "/test.Service/Method", recorded.FullMethod)
	assert.Equal(t, "client_certificate_not_authorized_for_tenant", recorded.Reason)
	assert.Equal(t, []string{"proxy-a.firewall.local"}, recorded.ClientIdentities)
}

func TestTenantAuthorizationStreamInterceptor_AuthorizesDecodedTenant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		request      streamTenantRequest
		wantCode     codes.Code
		wantReceived bool
	}{
		{
			name:         "authorized tenant",
			request:      streamTenantRequest{TenantID: "tenant-a"},
			wantCode:     codes.OK,
			wantReceived: true,
		},
		{
			name:     "different tenant",
			request:  streamTenantRequest{TenantID: "tenant-b"},
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "missing tenant",
			request:  streamTenantRequest{},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			interceptor := TenantAuthorizationStreamInterceptor(
				[]config.BundleTLSAuthorizedClient{
					{Identity: "worker-a.firewall.local", TenantIDs: []string{"tenant-a"}},
				},
				func(req any) string { return req.(*streamTenantRequest).TenantID },
			)
			ctx := peer.NewContext(context.Background(), &peer.Peer{
				AuthInfo: credentials.TLSInfo{
					State: tlsConnectionState(&x509.Certificate{DNSNames: []string{"worker-a.firewall.local"}}),
				},
			})
			stream := &testServerStream{ctx: ctx, request: tt.request}
			received := false

			err := interceptor(
				nil,
				stream,
				&grpc.StreamServerInfo{FullMethod: "/test.Service/Watch"},
				func(_ any, stream grpc.ServerStream) error {
					if err := stream.RecvMsg(&streamTenantRequest{}); err != nil {
						return err
					}
					received = true
					return nil
				},
			)

			assert.Equal(t, tt.wantCode, status.Code(err))
			assert.Equal(t, tt.wantReceived, received)
		})
	}
}

type streamTenantRequest struct {
	TenantID string
}

type testServerStream struct {
	ctx     context.Context
	request streamTenantRequest
}

func (s *testServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *testServerStream) SendHeader(metadata.MD) error { return nil }
func (s *testServerStream) SetTrailer(metadata.MD)       {}
func (s *testServerStream) Context() context.Context     { return s.ctx }
func (s *testServerStream) SendMsg(any) error            { return nil }
func (s *testServerStream) RecvMsg(message any) error {
	*message.(*streamTenantRequest) = s.request
	return nil
}

func tlsConnectionState(cert *x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}
