package errutil

import (
	"context"
	"errors"
)

// IsCanceled reports whether err wraps context.Canceled.
func IsCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}

// IsCanceledContext reports whether ctx has been canceled by the caller.
func IsCanceledContext(ctx context.Context) bool {
	return ctx != nil && IsCanceled(ctx.Err())
}

// IsDeadlineExceeded reports whether err wraps context.DeadlineExceeded.
func IsDeadlineExceeded(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

// IsDeadlineExceededContext reports whether ctx has exceeded its deadline.
func IsDeadlineExceededContext(ctx context.Context) bool {
	return ctx != nil && IsDeadlineExceeded(ctx.Err())
}
