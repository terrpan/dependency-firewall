package npm

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// addWarningHeaders writes policy warnings as npm-notice headers so npm
// displays them to the user during install.
func addWarningHeaders(w http.ResponseWriter, decision *domain.Decision) {
	for _, warning := range decision.Warnings {
		w.Header().Add("npm-notice", warning)
	}
}

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

type npmErrorResponse struct {
	Error string `json:"error"`
}

func writeNPMError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(npmErrorResponse{Error: message})
}
