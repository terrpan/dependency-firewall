package controlplanegrpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
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

	_, err := interceptor(ctx, struct{}{}, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, "tenant-b", recorded.TenantID)
	assert.Equal(t, "/test.Service/Method", recorded.FullMethod)
	assert.Equal(t, "client_certificate_not_authorized_for_tenant", recorded.Reason)
	assert.Equal(t, []string{"proxy-a.firewall.local"}, recorded.ClientIdentities)
}

func tlsConnectionState(cert *x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}
