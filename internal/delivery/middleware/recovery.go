package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recovery returns middleware that recovers from panics, logs the stack trace,
// and returns a 500 response.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					attrs := []any{
						"error", rec,
						"stack", string(debug.Stack()),
						"method", r.Method,
						"path", r.URL.Path,
					}
					if requestID, ok := RequestIDFromContext(r.Context()); ok {
						attrs = append(attrs, "request_id", requestID)
					}
					logger.Error("panic recovered", attrs...)
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
