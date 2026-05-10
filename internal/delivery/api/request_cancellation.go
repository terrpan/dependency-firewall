package api

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/errutil"
)

const statusClientClosedRequest = 499

const controlPlaneReadTimeout = 10 * time.Second

func isCanceledRequest(ctx context.Context, err error) bool {
	return errutil.IsCanceled(err) || errutil.IsCanceledContext(ctx)
}

func isTimedOutRequest(ctx context.Context, err error) bool {
	return errutil.IsDeadlineExceeded(err) || errutil.IsDeadlineExceededContext(ctx)
}

func withControlPlaneReadTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, controlPlaneReadTimeout)
}

func controlPlaneErrors(statuses ...int) []int {
	return appendControlPlaneErrors(statuses, statusClientClosedRequest)
}

func controlPlaneReadErrors(statuses ...int) []int {
	return appendControlPlaneErrors(statuses, statusClientClosedRequest, http.StatusGatewayTimeout)
}

func appendControlPlaneErrors(statuses []int, additions ...int) []int {
	merged := make([]int, 0, len(statuses)+len(additions))
	for _, status := range append(statuses, additions...) {
		if !slices.Contains(merged, status) {
			merged = append(merged, status)
		}
	}
	return merged
}

func humaInternalError(ctx context.Context, logger *slog.Logger, logMessage string, err error, clientMessage string, attrs ...any) error {
	if isCanceledRequest(ctx, err) {
		return huma.NewError(statusClientClosedRequest, "request canceled")
	}

	if isTimedOutRequest(ctx, err) {
		if logger != nil {
			logAttrs := make([]any, 0, len(attrs)+2)
			logAttrs = append(logAttrs, "error", err)
			logAttrs = append(logAttrs, attrs...)
			logger.WarnContext(ctx, logMessage+" timed out", logAttrs...)
		}
		return huma.NewError(http.StatusGatewayTimeout, "request timed out")
	}

	if logger != nil {
		logAttrs := make([]any, 0, len(attrs)+2)
		logAttrs = append(logAttrs, "error", err)
		logAttrs = append(logAttrs, attrs...)
		logger.ErrorContext(ctx, logMessage, logAttrs...)
	}

	return huma.Error500InternalServerError(clientMessage)
}
