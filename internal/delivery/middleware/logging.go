package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// RequestLogging returns middleware that logs each request with structured fields.
func RequestLogging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(rw, r)

			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rw.statusCode),
				slog.Duration("duration", time.Since(start)),
			}

			if tenant, ok := TenantFromContext(r.Context()); ok {
				attrs = append(attrs, slog.String("tenant_id", tenant.ID))
			}
			if requestID, ok := RequestIDFromContext(r.Context()); ok {
				attrs = append(attrs, slog.String("request_id", requestID))
			}

			logger.LogAttrs(r.Context(), slog.LevelInfo, "request completed", attrs...)
		})
	}
}
