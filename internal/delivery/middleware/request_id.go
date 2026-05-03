package middleware

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"
)

type requestIDContextKey struct{}

const requestIDHeader = "X-Request-ID"

// RequestID returns middleware that propagates or generates a request correlation ID.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get(requestIDHeader)
			if requestID == "" {
				requestID = newRequestID()
			}

			w.Header().Set(requestIDHeader, requestID)
			ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequestIDFromContext returns the request correlation ID when present.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(requestIDContextKey{}).(string)
	return value, ok && value != ""
}

func newRequestID() string {
	var bytes [6]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("req-%s-fallback", time.Now().UTC().Format("20060102-150405"))
	}

	return fmt.Sprintf("req-%s-%x", time.Now().UTC().Format("20060102-150405"), bytes)
}
