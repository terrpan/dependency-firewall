package upstream

import (
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/port"
)

var forwardedResponseHeaders = [...]string{
	"Docker-Content-Digest",
	"Content-Type",
	"Content-Length",
	"ETag",
}

func extractHeaders(resp *http.Response) map[string]string {
	headers := make(map[string]string, len(forwardedResponseHeaders))
	for _, h := range forwardedResponseHeaders {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	return headers
}

func newUpstreamResponse(resp *http.Response) *port.UpstreamResponse {
	headers := extractHeaders(resp)
	return &port.UpstreamResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Headers:     headers,
		Body:        resp.Body,
	}
}
