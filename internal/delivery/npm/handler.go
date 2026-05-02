// Package npm implements npm registry protocol handlers.
package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

// RegistryHandler handles npm registry protocol requests.
type RegistryHandler struct {
	access    *service.AccessService
	upstream  port.UpstreamClient
	upstreams port.UpstreamRepository
	logger    *slog.Logger
}

// NewRegistryHandler creates a new npm RegistryHandler.
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

// RegisterRoutes registers npm protocol routes on the given mux.
func (h *RegistryHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /npm/{package...}", h.route)
}

// route dispatches requests based on path structure.
func (h *RegistryHandler) route(w http.ResponseWriter, r *http.Request) {
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
func (h *RegistryHandler) handleMetadata(w http.ResponseWriter, r *http.Request, path string) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeNPMError(w, "tenant not identified", http.StatusUnauthorized)
		return
	}

	upstream, err := h.resolveUpstream(r.Context(), tenant.ID)
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

	decision, err := h.access.Evaluate(r.Context(), req)
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

	addWarningHeaders(w, decision)

	resp, err := h.upstream.FetchMetadata(r.Context(), *upstream, artifact)
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

	if isJSONContentType(resp.ContentType) {
		rewrittenBody, rewriteErr := rewriteMetadataTarballs(r, resp.Body, tenant.ID, upstream.ID)
		if rewriteErr != nil {
			h.logger.Error("failed to rewrite npm metadata tarball URLs",
				"error", rewriteErr,
				"tenant_id", tenant.ID,
				"package", name,
			)
			writeNPMError(w, "upstream metadata error", http.StatusBadGateway)
			return
		}
		resp.Body = io.NopCloser(bytes.NewReader(rewrittenBody))
		if resp.Headers == nil {
			resp.Headers = make(map[string]string)
		}
		delete(resp.Headers, "ETag")
		resp.Headers["Content-Length"] = strconv.Itoa(len(rewrittenBody))
	}

	streamResponse(w, resp)
}

// handleTarball processes tarball download requests.
func (h *RegistryHandler) handleTarball(w http.ResponseWriter, r *http.Request, name, version string) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeNPMError(w, "tenant not identified", http.StatusUnauthorized)
		return
	}

	upstream, err := h.resolveUpstream(r.Context(), tenant.ID)
	if err != nil {
		writeNPMError(w, "no npm upstream configured", http.StatusNotFound)
		return
	}

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

	decision, err := h.access.Evaluate(r.Context(), req)
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

	addWarningHeaders(w, decision)

	// Use the tarball filename as the digest/identifier for the blob fetch.
	tarball := tarballFilename(name, version)
	resp, err := h.upstream.FetchContent(r.Context(), *upstream, tarball)
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
	before, after, ok0 := strings.Cut(path, "/-/")
	if !ok0 {
		return "", "", false
	}

	name = before
	filename := after // after "/-/"

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

// addWarningHeaders writes policy warnings as npm-notice headers so npm
// displays them to the user during install.
func addWarningHeaders(w http.ResponseWriter, decision *domain.Decision) {
	for _, warning := range decision.Warnings {
		w.Header().Add("npm-notice", warning)
	}
}

func isJSONContentType(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func rewriteMetadataTarballs(r *http.Request, body io.Reader, tenantID, upstreamID string) ([]byte, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	proxyBase := npmProxyBaseURL(r, tenantID, upstreamID)
	rewriteTarballURLs(payload, proxyBase)

	rewritten, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return rewritten, nil
}

func rewriteTarballURLs(value any, proxyBase string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			rewriteTarballURLs(child, proxyBase)
			if key != "tarball" {
				continue
			}
			tarball, ok := child.(string)
			if !ok || strings.TrimSpace(tarball) == "" {
				continue
			}
			typed[key] = proxyBase + strings.TrimPrefix(tarballPath(tarball), "/")
		}
	case []any:
		for _, child := range typed {
			rewriteTarballURLs(child, proxyBase)
		}
	}
}

func tarballPath(tarballURL string) string {
	parsed, err := url.Parse(tarballURL)
	if err != nil {
		return tarballURL
	}
	if parsed.RawPath != "" {
		return parsed.RawPath
	}
	if parsed.Path != "" {
		return parsed.Path
	}
	return tarballURL
}

func npmProxyBaseURL(r *http.Request, tenantID, upstreamID string) string {
	base := requestBaseURL(r)
	var path strings.Builder
	path.WriteString("/npm/t/")
	path.WriteString(tenantID)
	path.WriteByte('/')
	if upstreamID != "" {
		path.WriteString("u/")
		path.WriteString(upstreamID)
		path.WriteByte('/')
	}
	return strings.TrimRight(base, "/") + path.String()
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); forwardedProto != "" {
		scheme = forwardedProto
	}

	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}

	return scheme + "://" + host
}

func firstHeaderValue(value string) string {
	if value == "" {
		return ""
	}
	part, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(part)
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

func (h *RegistryHandler) resolveUpstream(ctx context.Context, tenantID string) (*domain.Upstream, error) {
	if upstreamID, ok := middleware.UpstreamIDFromContext(ctx); ok && upstreamID != "" {
		upstream, err := h.upstreams.GetByID(ctx, tenantID, upstreamID)
		if err != nil {
			return nil, err
		}
		if upstream.Ecosystem != domain.EcosystemNPM {
			return nil, domain.ErrUpstreamNotFound
		}
		return upstream, nil
	}

	return h.upstreams.GetByEcosystem(ctx, tenantID, domain.EcosystemNPM)
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
