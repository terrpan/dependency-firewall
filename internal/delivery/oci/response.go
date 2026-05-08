package oci

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// streamResponse copies upstream response headers and body to the client.
func streamResponse(w http.ResponseWriter, resp *port.UpstreamResponse) {
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	if resp.ContentType != "" {
		w.Header().Set("Content-Type", resp.ContentType)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ociErrorResponse is the OCI-spec error envelope.
type ociErrorResponse struct {
	Errors []ociError `json:"errors"`
}

type ociError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail"`
}

// writeOCIError writes an OCI-spec error response.
func writeOCIError(w http.ResponseWriter, r *http.Request, code string, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("X-Dependency-Firewall-Reason", message)
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(ociErrorResponse{
		Errors: []ociError{{Code: code, Message: message, Detail: map[string]any{}}},
	})
}
