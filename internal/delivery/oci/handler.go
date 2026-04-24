// Package oci implements OCI registry protocol handlers.
package oci

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

// RegistryHandler handles OCI registry protocol requests.
type RegistryHandler struct {
	access    *service.AccessService
	upstream  port.UpstreamClient
	upstreams port.UpstreamRepository
	logger    *slog.Logger
}

// NewRegistryHandler creates a new OCI RegistryHandler.
func NewRegistryHandler(
	access *service.AccessService,
	upstream port.UpstreamClient,
	upstreams port.UpstreamRepository,
	logger *slog.Logger,
) *RegistryHandler {
	return &RegistryHandler{
		access:    access,
		upstream:  upstream,
		upstreams: upstreams,
		logger:    logger,
	}
}

// RegisterRoutes registers OCI protocol routes on the given mux.
func (h *RegistryHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v2/", h.route)
}

// route dispatches requests based on path structure.
func (h *RegistryHandler) route(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// GET /v2/ — version check
	if path == "/v2/" || path == "/v2" {
		h.versionCheck(w, r)
		return
	}

	// Strip leading /v2/ prefix.
	rest := strings.TrimPrefix(path, "/v2/")

	// Try to match /v2/{repo}/manifests/{reference}
	if repo, ref, ok := parseManifestPath(rest); ok {
		h.handleManifest(w, r, repo, ref)
		return
	}

	// Try to match /v2/{repo}/blobs/{digest}
	if repo, digest, ok := parseBlobPath(rest); ok {
		h.handleBlob(w, r, repo, digest)
		return
	}

	writeOCIError(w, "NAME_UNKNOWN", "unsupported OCI endpoint", http.StatusNotFound)
}

// versionCheck implements the OCI version check endpoint.
func (h *RegistryHandler) versionCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// handleManifest processes manifest pull requests.
func (h *RegistryHandler) handleManifest(w http.ResponseWriter, r *http.Request, repo, reference string) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeOCIError(w, "UNAUTHORIZED", "tenant not identified", http.StatusUnauthorized)
		return
	}

	upstream, err := h.upstreams.GetByEcosystem(r.Context(), tenant.ID, domain.EcosystemOCI)
	if err != nil {
		h.logger.Error("failed to look up OCI upstream",
			"error", err,
			"tenant_id", tenant.ID,
		)
		writeOCIError(w, "NAME_UNKNOWN", "no OCI upstream configured", http.StatusNotFound)
		return
	}

	namespace, name := splitRepo(repo)
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: namespace,
		Name:      name,
		Version:   reference,
	}

	req := domain.AccessRequest{
		TenantID:  tenant.ID,
		Artifact:  artifact,
		Upstream:  *upstream,
		Timestamp: time.Now(),
	}

	decision, err := h.access.Evaluate(r.Context(), req)
	if err != nil {
		h.logger.Error("policy evaluation failed",
			"error", err,
			"tenant_id", tenant.ID,
			"repo", repo,
			"reference", reference,
		)
		writeOCIError(w, "DENIED", "policy evaluation error", http.StatusInternalServerError)
		return
	}

	if decision.Outcome == domain.DecisionDeny {
		writeOCIError(w, "DENIED", "policy violation: "+decision.Reason, http.StatusForbidden)
		return
	}

	// Allowed — fetch from upstream and stream to client.
	resp, err := h.upstream.FetchMetadata(r.Context(), *upstream, artifact)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeOCIError(w, "MANIFEST_UNKNOWN", "manifest not found", http.StatusNotFound)
			return
		}
		h.logger.Error("upstream manifest fetch failed",
			"error", err,
			"tenant_id", tenant.ID,
			"repo", repo,
		)
		writeOCIError(w, "MANIFEST_UNKNOWN", "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	streamResponse(w, resp)
}

// handleBlob processes blob requests. Blobs are only served if the
// tenant has a recent manifest-level allow decision for the repository.
func (h *RegistryHandler) handleBlob(w http.ResponseWriter, r *http.Request, repo, digest string) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeOCIError(w, "UNAUTHORIZED", "tenant not identified", http.StatusUnauthorized)
		return
	}

	// Verify that a manifest-level allow decision exists for this repository.
	namespace, name := splitRepo(repo)
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: namespace,
		Name:      name,
	}
	allowed, err := h.access.HasRecentAllow(r.Context(), tenant.ID, artifact)
	if err != nil {
		h.logger.Error("failed to check manifest allow decision",
			"error", err,
			"tenant_id", tenant.ID,
			"repo", repo,
		)
		writeOCIError(w, "DENIED", "policy check error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		writeOCIError(w, "DENIED", "no manifest-level allow decision for this repository", http.StatusForbidden)
		return
	}

	upstream, err := h.upstreams.GetByEcosystem(r.Context(), tenant.ID, domain.EcosystemOCI)
	if err != nil {
		writeOCIError(w, "NAME_UNKNOWN", "no OCI upstream configured", http.StatusNotFound)
		return
	}

	// Build a modified upstream with the repo path baked into the BaseURL
	// so the upstream client can construct the correct blob URL.
	blobUpstream := *upstream
	blobUpstream.BaseURL = strings.TrimRight(upstream.BaseURL, "/") + "/v2/" + repo

	resp, err := h.upstream.FetchContent(r.Context(), blobUpstream, digest)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeOCIError(w, "BLOB_UNKNOWN", "blob not found", http.StatusNotFound)
			return
		}
		h.logger.Error("upstream blob fetch failed",
			"error", err,
			"tenant_id", tenant.ID,
			"repo", repo,
		)
		writeOCIError(w, "BLOB_UNKNOWN", "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	streamResponse(w, resp)
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

// parseManifestPath extracts repository and reference from a path like
// "library/nginx/manifests/latest".
func parseManifestPath(path string) (repo, reference string, ok bool) {
	const marker = "/manifests/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return "", "", false
	}
	repo = path[:idx]
	reference = path[idx+len(marker):]
	if repo == "" || reference == "" {
		return "", "", false
	}
	return repo, reference, true
}

// parseBlobPath extracts repository and digest from a path like
// "library/nginx/blobs/sha256:abc123".
func parseBlobPath(path string) (repo, digest string, ok bool) {
	const marker = "/blobs/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return "", "", false
	}
	repo = path[:idx]
	digest = path[idx+len(marker):]
	if repo == "" || digest == "" {
		return "", "", false
	}
	return repo, digest, true
}

// splitRepo splits a repository path into namespace and name.
// For "library/nginx" -> ("library", "nginx").
// For "nginx" -> ("", "nginx").
// For "a/b/c" -> ("a/b", "c").
func splitRepo(repo string) (namespace, name string) {
	idx := strings.LastIndex(repo, "/")
	if idx < 0 {
		return "", repo
	}
	return repo[:idx], repo[idx+1:]
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
func writeOCIError(w http.ResponseWriter, code string, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ociErrorResponse{
		Errors: []ociError{{Code: code, Message: message, Detail: map[string]any{}}},
	})
}
