// Package npm implements npm registry protocol handlers.
package npm

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

// Handler handles npm registry protocol requests.
type Handler struct {
	proxy     *service.ProxyService
	upstream  port.UpstreamClient
	upstreams port.UpstreamRepository
	logger    *slog.Logger
}

// NewHandler creates a new npm Handler.
func NewHandler(
	proxy *service.ProxyService,
	upstream port.UpstreamClient,
	upstreams port.UpstreamRepository,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		proxy:     proxy,
		upstream:  upstream,
		upstreams: upstreams,
		logger:    logger,
	}
}

// RegisterRoutes registers npm protocol routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /npm/{package...}", h.route)
}

// route dispatches requests based on path structure.
func (h *Handler) route(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/npm/")
	if path == "" {
		writeNPMError(w, "package name is required", http.StatusBadRequest)
		return
	}

	if name, version, ok := parseTarballPath(path); ok {
		h.handleTarball(w, r, name, version)
		return
	}

	h.handleMetadata(w, r, path)
}

// handleMetadata processes package metadata requests.
func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request, path string) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeNPMError(w, "tenant not identified", http.StatusUnauthorized)
		return
	}

	upstream, err := h.upstreams.GetByEcosystem(r.Context(), tenant.ID, domain.EcosystemNPM)
	if err != nil {
		h.logger.Error("failed to look up npm upstream",
			"error", err,
			"tenant_id", tenant.ID,
		)
		writeNPMError(w, "no npm upstream configured", http.StatusNotFound)
		return
	}

	name, version := parsePackagePath(path)
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      name,
		Version:   version,
	}

	req := domain.AccessRequest{
		TenantID:  tenant.ID,
		Artifact:  artifact,
		Upstream:  *upstream,
		Timestamp: time.Now(),
	}

	decision, err := h.proxy.Evaluate(r.Context(), req)
	if err != nil {
		h.logger.Error("policy evaluation failed",
			"error", err,
			"tenant_id", tenant.ID,
			"package", name,
			"version", version,
		)
		writeNPMError(w, "policy evaluation error", http.StatusInternalServerError)
		return
	}

	if decision.Outcome == domain.DecisionDeny {
		writeNPMError(w, "policy violation: "+decision.Reason, http.StatusForbidden)
		return
	}

	resp, err := h.upstream.GetManifest(r.Context(), *upstream, artifact)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeNPMError(w, "package not found", http.StatusNotFound)
			return
		}
		h.logger.Error("upstream metadata fetch failed",
			"error", err,
			"tenant_id", tenant.ID,
			"package", name,
		)
		writeNPMError(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	streamResponse(w, resp)
}

// handleTarball processes tarball download requests.
func (h *Handler) handleTarball(w http.ResponseWriter, r *http.Request, name, version string) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeNPMError(w, "tenant not identified", http.StatusUnauthorized)
		return
	}

	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      name,
	}
	// Normalize to extract scope into namespace.
	normalized, err := domain.NormalizeArtifactIdentity(artifact)
	if err != nil {
		writeNPMError(w, "invalid package reference", http.StatusBadRequest)
		return
	}

	allowed, err := h.proxy.HasAllowedManifest(r.Context(), tenant.ID, normalized)
	if err != nil {
		h.logger.Error("failed to check manifest allow decision",
			"error", err,
			"tenant_id", tenant.ID,
			"package", name,
		)
		writeNPMError(w, "policy check error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		writeNPMError(w, "no allow decision for this package", http.StatusForbidden)
		return
	}

	upstream, err := h.upstreams.GetByEcosystem(r.Context(), tenant.ID, domain.EcosystemNPM)
	if err != nil {
		writeNPMError(w, "no npm upstream configured", http.StatusNotFound)
		return
	}

	// Use the tarball filename as the digest/identifier for the blob fetch.
	tarball := tarballFilename(name, version)
	resp, err := h.upstream.GetBlob(r.Context(), *upstream, tarball)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeNPMError(w, "tarball not found", http.StatusNotFound)
			return
		}
		h.logger.Error("upstream tarball fetch failed",
			"error", err,
			"tenant_id", tenant.ID,
			"package", name,
			"version", version,
		)
		writeNPMError(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	streamResponse(w, resp)
}

// parsePackagePath extracts package name and optional version from the URL path.
//
//   - "@scope/name/version" → name="@scope/name", version="version"
//   - "@scope/name"         → name="@scope/name", version=""
//   - "name/version"        → name="name",        version="version"
//   - "name"                → name="name",        version=""
func parsePackagePath(path string) (name, version string) {
	if strings.HasPrefix(path, "@") {
		// Scoped: @scope/name or @scope/name/version
		parts := strings.SplitN(path, "/", 3)
		if len(parts) < 2 {
			return path, ""
		}
		name = parts[0] + "/" + parts[1]
		if len(parts) == 3 && parts[2] != "" {
			version = parts[2]
		}
		return name, version
	}

	// Unscoped: name or name/version
	parts := strings.SplitN(path, "/", 2)
	name = parts[0]
	if len(parts) == 2 && parts[1] != "" {
		version = parts[1]
	}
	return name, version
}

// parseTarballPath detects and parses tarball download URLs.
// Pattern: {@scope/name|-}/name-version.tgz  →  (fullName, version)
//
// Examples:
//   - "@scope/name/-/name-1.0.0.tgz"     → ("@scope/name", "1.0.0")
//   - "name/-/name-1.0.0.tgz"            → ("name", "1.0.0")
func parseTarballPath(path string) (name, version string, ok bool) {
	idx := strings.Index(path, "/-/")
	if idx < 0 {
		return "", "", false
	}

	name = path[:idx]
	filename := path[idx+3:] // after "/-/"

	if !strings.HasSuffix(filename, ".tgz") {
		return "", "", false
	}
	filename = strings.TrimSuffix(filename, ".tgz")

	// The filename is "{basename}-{version}" where basename is the
	// unscoped name (the part after scope/ if scoped).
	basename := name
	if slashIdx := strings.LastIndex(name, "/"); slashIdx >= 0 {
		basename = name[slashIdx+1:]
	}

	prefix := basename + "-"
	if !strings.HasPrefix(filename, prefix) {
		return "", "", false
	}
	version = filename[len(prefix):]
	if version == "" {
		return "", "", false
	}

	return name, version, true
}

// tarballFilename constructs the tarball path segment used for upstream blob fetch.
func tarballFilename(name, version string) string {
	basename := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		basename = name[idx+1:]
	}
	return name + "/-/" + basename + "-" + version + ".tgz"
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

// npmErrorResponse is the npm-compatible error format.
type npmErrorResponse struct {
	Error string `json:"error"`
}

// writeNPMError writes an npm-compatible error response.
func writeNPMError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(npmErrorResponse{Error: message})
}
