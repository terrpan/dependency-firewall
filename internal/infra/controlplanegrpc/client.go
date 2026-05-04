package controlplanegrpc

import (
	"encoding/json"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

// NewClientConn creates a control-plane gRPC client connection using the shared
// JSON codec and telemetry dial options.
func NewClientConn(address string) (*grpc.ClientConn, error) {
	return grpc.NewClient(address, DialOptions()...)
}

// DialOptions returns the shared client dial options for control-plane gRPC
// traffic.
func DialOptions() []grpc.DialOption {
	return append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	}, telemetry.ClientDialOptions()...)
}

// ServerOptions returns the shared server options for control-plane gRPC
// traffic.
func ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{grpc.ForceServerCodec(jsonCodec{})}
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
