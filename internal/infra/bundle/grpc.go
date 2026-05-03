package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/delivery/bundlegrpc"
)

// GRPCClient fetches tenant bundles from the control plane over gRPC.
type GRPCClient struct {
	conn *grpc.ClientConn
}

// NewGRPCClient creates a new GRPCClient.
func NewGRPCClient(ctx context.Context, address string) (*GRPCClient, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		dialCtx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	)
	if err != nil {
		return nil, fmt.Errorf("dialing bundle service: %w", err)
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
	return bundlegrpc.GetTenantBundle(ctx, c.conn, tenantID)
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
