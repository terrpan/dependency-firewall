// Package npm implements npm registry protocol handlers.
package npm

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
	"github.com/danielterry/dependency-firewall/internal/delivery/proxyflow"
)

// RegistryHandler handles npm registry protocol requests.
type RegistryHandler struct {
	access    *service.AccessService
	audit     *service.AuditService
	upstream  port.UpstreamClient
	upstreams port.UpstreamRepository
	snapshots *service.NPMInstallSnapshotService
	logger    *slog.Logger
}

type npmAccessContext struct {
	tenantID string
	upstream domain.Upstream
	artifact domain.ArtifactIdentity
	audit    proxyflow.AuditContext
	decision *domain.Decision
}

// NewRegistryHandler creates a new npm RegistryHandler. snapshots may be nil
// when install-snapshot root inference is not wired for the runtime.
func NewRegistryHandler(
	access *service.AccessService,
	upstream port.UpstreamClient,
	upstreams port.UpstreamRepository,
	logger *slog.Logger,
	audit *service.AuditService,
	snapshots *service.NPMInstallSnapshotService,
) *RegistryHandler {
	return &RegistryHandler{
		access:    access,
		audit:     audit,
		upstream:  upstream,
		upstreams: upstreams,
		snapshots: snapshots,
		logger:    logger,
	}
}

// RegisterRoutes registers npm protocol routes on the given mux.
func (h *RegistryHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /npm/{package...}", h.route)
	mux.HandleFunc("POST /npm/{path...}", h.routePost)
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
	name, version := parsePackagePath(path)
	access, ok := h.startNPMRequest(
		w,
		r,
		name,
		version,
		domain.AccessRequestKindNPMMetadata,
		"metadata",
		true,
	)
	if !ok || !h.authorizeMetadata(w, r, access, version) {
		return
	}
	if err := proxyflow.RecordUpstreamFetchStarted(
		r.Context(),
		h.audit,
		access.audit,
		"npm upstream metadata fetch started",
	); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	resp, ok := h.fetchMetadataResponse(
		w,
		r,
		access.upstream,
		access.artifact,
		access.audit,
		access.tenantID,
		name,
	)
	if !ok {
		return
	}
	defer resp.Body.Close()

	if !h.rewriteMetadataResponse(w, r, resp, access.tenantID, access.upstream.ID, name) {
		return
	}
	streamResponse(w, resp)
}

func (h *RegistryHandler) startNPMRequest(
	w http.ResponseWriter,
	r *http.Request,
	name, version string,
	kind domain.AccessRequestKind,
	operation string,
	logUpstreamLookupError bool,
) (*npmAccessContext, bool) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeNPMError(w, "tenant not identified", http.StatusUnauthorized)
		return nil, false
	}
	upstream, err := proxyflow.ResolveUpstream(r.Context(), h.upstreams, tenant.ID, domain.EcosystemNPM)
	if err != nil {
		if logUpstreamLookupError {
			h.logger.Error("failed to look up npm upstream", "error", err, "tenant_id", tenant.ID)
		}
		writeNPMError(w, "no npm upstream configured", http.StatusNotFound)
		return nil, false
	}

	artifact := domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: name, Version: version}
	req := proxyflow.NewAccessRequest(r.Context(), tenant.ID, *upstream, artifact)
	req.Kind = kind
	audit := proxyflow.AuditContext{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		Source:        "delivery/npm",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Operation:     operation,
	}
	if err := proxyflow.RecordRequestReceived(
		r.Context(),
		h.audit,
		audit,
		r,
		"npm "+operation+" request received",
		nil,
	); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return nil, false
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
		return nil, false
	}
	return &npmAccessContext{
		tenantID: tenant.ID,
		upstream: *upstream,
		artifact: artifact,
		audit:    audit,
		decision: decision,
	}, true
}

func (h *RegistryHandler) authorizeMetadata(
	w http.ResponseWriter,
	r *http.Request,
	access *npmAccessContext,
	version string,
) bool {
	if access.decision.Outcome == domain.DecisionDeny {
		if err := proxyflow.RecordRequestDenied(
			r.Context(),
			h.audit,
			access.audit,
			access.decision,
			"npm metadata request denied",
		); err != nil {
			writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
			return false
		}
		writeNPMError(w, "policy violation: "+access.decision.Reason, http.StatusForbidden)
		return false
	}

	addWarningHeaders(w, access.decision)
	if version == "" {
		if err := proxyflow.RecordRequestForwarded(
			r.Context(),
			h.audit,
			access.audit,
			access.decision,
			"bare npm packument; concrete version will be evaluated on versioned metadata or tarball request",
			"npm metadata request forwarded",
		); err != nil {
			writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
			return false
		}
		return true
	}
	if err := proxyflow.RecordRequestAllowed(
		r.Context(),
		h.audit,
		access.audit,
		access.decision,
		"npm metadata request allowed",
	); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *RegistryHandler) fetchMetadataResponse(
	w http.ResponseWriter,
	r *http.Request,
	upstream domain.Upstream,
	artifact domain.ArtifactIdentity,
	audit proxyflow.AuditContext,
	tenantID, name string,
) (*port.UpstreamResponse, bool) {
	resp, err := h.upstream.FetchMetadata(r.Context(), upstream, artifact)
	if err == nil {
		return resp, true
	}
	if errors.Is(err, domain.ErrArtifactNotFound) {
		writeNPMError(w, "package not found", http.StatusNotFound)
		return nil, false
	}
	_ = proxyflow.RecordUpstreamFetchFailed(r.Context(), h.audit, audit, "npm upstream metadata fetch failed", err)
	h.logger.Error("upstream metadata fetch failed",
		"error", err,
		"tenant_id", tenantID,
		"package", name,
	)
	writeNPMError(w, "upstream error", http.StatusBadGateway)
	return nil, false
}

func (h *RegistryHandler) rewriteMetadataResponse(
	w http.ResponseWriter,
	r *http.Request,
	resp *port.UpstreamResponse,
	tenantID, upstreamID, name string,
) bool {
	if !isJSONContentType(resp.ContentType) {
		return true
	}

	rewrittenBody, err := rewriteMetadataTarballs(r, resp.Body, tenantID, upstreamID)
	if err != nil {
		h.logger.Error("failed to rewrite npm metadata tarball URLs",
			"error", err,
			"tenant_id", tenantID,
			"package", name,
		)
		writeNPMError(w, "upstream metadata error", http.StatusBadGateway)
		return false
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewrittenBody))
	if resp.Headers == nil {
		resp.Headers = make(map[string]string)
	}
	delete(resp.Headers, "ETag")
	resp.Headers["Content-Length"] = strconv.Itoa(len(rewrittenBody))
	return true
}

// handleTarball processes tarball download requests.
func (h *RegistryHandler) handleTarball(w http.ResponseWriter, r *http.Request, name, version string) {
	access, ok := h.startNPMRequest(
		w,
		r,
		name,
		version,
		domain.AccessRequestKindNPMTarball,
		"tarball",
		false,
	)
	if !ok || !h.authorizeTarball(w, r, access) {
		return
	}
	if err := proxyflow.RecordUpstreamFetchStarted(
		r.Context(),
		h.audit,
		access.audit,
		"npm upstream tarball fetch started",
	); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	h.streamTarball(w, r, access.upstream, access.audit, access.tenantID, name, version)
}

func (h *RegistryHandler) authorizeTarball(
	w http.ResponseWriter,
	r *http.Request,
	access *npmAccessContext,
) bool {
	if access.decision.Outcome == domain.DecisionDeny {
		if err := proxyflow.RecordRequestDenied(
			r.Context(),
			h.audit,
			access.audit,
			access.decision,
			"npm tarball request denied",
		); err != nil {
			writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
			return false
		}
		writeNPMError(w, "policy violation: "+access.decision.Reason, http.StatusForbidden)
		return false
	}

	addWarningHeaders(w, access.decision)
	if err := proxyflow.RecordRequestAllowed(
		r.Context(),
		h.audit,
		access.audit,
		access.decision,
		"npm tarball request allowed",
	); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *RegistryHandler) streamTarball(
	w http.ResponseWriter,
	r *http.Request,
	upstream domain.Upstream,
	audit proxyflow.AuditContext,
	tenantID, name, version string,
) {
	// Use the tarball filename as the digest/identifier for the blob fetch.
	tarball := tarballFilename(name, version)
	resp, err := h.upstream.FetchContent(r.Context(), upstream, tarball)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeNPMError(w, "tarball not found", http.StatusNotFound)
			return
		}
		_ = proxyflow.RecordUpstreamFetchFailed(r.Context(), h.audit, audit, "npm upstream tarball fetch failed", err)
		h.logger.Error("upstream tarball fetch failed",
			"error", err,
			"tenant_id", tenantID,
			"package", name,
			"version", version,
		)
		writeNPMError(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	streamResponse(w, resp)
}
