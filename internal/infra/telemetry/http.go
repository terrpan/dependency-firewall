package telemetry

import (
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// WrapHTTPClient returns a copy of client with an instrumented transport.
func WrapHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}

	clone := *client
	transport := clone.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	clone.Transport = otelhttp.NewTransport(transport)

	return &clone
}

// WrapHTTPHandler instruments incoming HTTP requests with low-cardinality span names.
func WrapHTTPHandler(handler http.Handler) http.Handler {
	return otelhttp.NewHandler(
		handler,
		"http.server",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return spanNameForRequest(r)
		}),
	)
}

func spanNameForRequest(r *http.Request) string {
	path := r.URL.Path
	switch {
	case path == "/healthz":
		return r.Method + " /healthz"
	case strings.HasPrefix(path, "/api/"):
		return r.Method + " /api"
	case strings.HasPrefix(path, "/npm/"):
		if strings.Contains(path, "/-/") || strings.HasSuffix(path, ".tgz") {
			return r.Method + " /npm/tarball"
		}
		return r.Method + " /npm/metadata"
	case strings.HasPrefix(path, "/v2/"):
		switch {
		case path == "/v2/" || path == "/v2":
			return r.Method + " /v2"
		case strings.Contains(path, "/manifests/"):
			return r.Method + " /v2/manifests"
		case strings.Contains(path, "/blobs/"):
			return r.Method + " /v2/blobs"
		default:
			return r.Method + " /v2"
		}
	default:
		return fmt.Sprintf("%s %s", r.Method, path)
	}
}
