package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHumaInternalError_RequestCanceledReturnsClientClosed(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := humaInternalError(ctx, logger, "listing evaluations", context.Canceled, "failed to list evaluations")

	statusErr, ok := err.(huma.StatusError)
	require.True(t, ok)
	assert.Equal(t, statusClientClosedRequest, statusErr.GetStatus())
	assert.Equal(t, "request canceled", statusErr.Error())
	assert.Empty(t, logs.String())
}

func TestHumaInternalError_DeadlineExceededReturnsGatewayTimeout(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := humaInternalError(ctx, logger, "listing evaluations", context.DeadlineExceeded, "failed to list evaluations")

	statusErr, ok := err.(huma.StatusError)
	require.True(t, ok)
	assert.Equal(t, http.StatusGatewayTimeout, statusErr.GetStatus())
	assert.Equal(t, "request timed out", statusErr.Error())
	assert.Contains(t, logs.String(), "listing evaluations timed out")
}

func TestHumaInternalError_UnexpectedErrorLogsAndReturnsInternalServerError(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	err := humaInternalError(
		context.Background(),
		logger,
		"listing evaluations",
		errors.New("database unavailable"),
		"failed to list evaluations",
		"tenant_id", "tenant-1",
	)

	statusErr, ok := err.(huma.StatusError)
	require.True(t, ok)
	assert.Equal(t, 500, statusErr.GetStatus())
	assert.Equal(t, "failed to list evaluations", statusErr.Error())
	assert.Contains(t, logs.String(), "listing evaluations")
	assert.Contains(t, logs.String(), "tenant-1")
}
