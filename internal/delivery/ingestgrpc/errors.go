package ingestgrpc

import (
	wire "github.com/danielterry/dependency-firewall/internal/wire/ingestgrpc"
)

func toStatusError(err error) error {
	return wire.ToStatusError(err)
}

func mapClientError(err error) error {
	return wire.MapClientError(err)
}
