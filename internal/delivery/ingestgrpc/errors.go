package ingestgrpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func toStatusError(err error) error {
	switch {
	case errors.Is(err, domain.ErrArtifactNotFound):
		return status.Error(codes.NotFound, domain.ErrArtifactNotFound.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func mapClientError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	if st.Code() == codes.NotFound && st.Message() == domain.ErrArtifactNotFound.Error() {
		return domain.ErrArtifactNotFound
	}
	return err
}
