package bundle

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/infra/controlplanegrpc"
	bundlewire "github.com/danielterry/dependency-firewall/internal/wire/bundlegrpc"
)

// GRPCClient fetches tenant bundles from the control plane over gRPC.
type GRPCClient struct {
	conn *grpc.ClientConn
}

// NewGRPCClient dials the control plane's bundle service and returns a client for fetching tenant bundles. The
// optional TLS configs supply the mTLS identity the control plane authorizes the proxy by; the connection is lazy, so
// dialing failures surface on the first fetch rather than here. Callers must Close the returned client.
func NewGRPCClient(_ context.Context, address string, configs ...config.BundleTLSConfig) (*GRPCClient, error) {
	conn, err := controlplanegrpc.NewClientConn(address, configs...)
	if err != nil {
		return nil, fmt.Errorf("creating bundle service client: %w", err)
	}

	return &GRPCClient{conn: conn}, nil
}

// Close closes the underlying client connection.
func (c *GRPCClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// GetTenantBundle fetches a tenant bundle.
func (c *GRPCClient) GetTenantBundle(ctx context.Context, tenantID string) (*domain.TenantBundle, error) {
	response, err := bundlewire.FetchTenantBundleResponse(ctx, c.conn, tenantID)
	if err != nil {
		return nil, err
	}
	return response.Bundle.ToDomain()
}
