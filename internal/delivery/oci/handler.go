// Package oci implements OCI registry protocol handlers.
package oci

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
	"github.com/danielterry/dependency-firewall/internal/delivery/proxyflow"
)

// RegistryHandler handles OCI registry protocol requests.
type RegistryHandler struct {
	access    *service.AccessService
	audit     *service.AuditService
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
	audit *service.AuditService,
) *RegistryHandler {
	return &RegistryHandler{
		access:    access,
		audit:     audit,
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

	writeOCIError(w, r, "NAME_UNKNOWN", "unsupported OCI endpoint", http.StatusNotFound)
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
		writeOCIError(w, r, "UNAUTHORIZED", "tenant not identified", http.StatusUnauthorized)
		return
	}

	upstream, err := proxyflow.ResolveUpstream(r.Context(), h.upstreams, tenant.ID, domain.EcosystemOCI)
	if err != nil {
		h.logger.Error("failed to look up OCI upstream",
			"error", err,
			"tenant_id", tenant.ID,
		)
		writeOCIError(w, r, "NAME_UNKNOWN", "no OCI upstream configured", http.StatusNotFound)
		return
	}

	namespace, name := splitRepo(repo)
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: namespace,
		Name:      name,
		Version:   reference,
	}

	req := proxyflow.NewAccessRequest(r.Context(), tenant.ID, *upstream, artifact)
	audit := proxyflow.AuditContext{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		Source:        "delivery/oci",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Operation:     "manifest",
	}
	if err := proxyflow.RecordRequestReceived(
		r.Context(),
		h.audit,
		audit,
		r,
		"oci manifest request received",
		map[string]any{
			"reference":  reference,
			"repository": repo,
		},
	); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	decision, err := h.access.Evaluate(r.Context(), req)
	if err != nil {
		h.logger.Error("policy evaluation failed",
			"error", err,
			"tenant_id", tenant.ID,
			"repo", repo,
			"reference", reference,
		)
		writeOCIError(w, r, "DENIED", "policy evaluation error", http.StatusInternalServerError)
		return
	}

	if !h.authorizeManifest(w, r, audit, decision) {
		return
	}
	h.streamManifest(w, r, *upstream, audit, decision.Artifact, tenant.ID, repo)
}

func (h *RegistryHandler) authorizeManifest(
	w http.ResponseWriter,
	r *http.Request,
	audit proxyflow.AuditContext,
	decision *domain.Decision,
) bool {
	if decision.Outcome == domain.DecisionDeny {
		if err := proxyflow.RecordRequestDenied(
			r.Context(),
			h.audit,
			audit,
			decision,
			"oci manifest request denied",
		); err != nil {
			writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
			return false
		}
		writeOCIError(w, r, "DENIED", "policy violation: "+decision.Reason, http.StatusForbidden)
		return false
	}
	if err := proxyflow.RecordRequestAllowed(
		r.Context(),
		h.audit,
		audit,
		decision,
		"oci manifest request allowed",
	); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return false
	}
	if err := proxyflow.RecordUpstreamFetchStarted(
		r.Context(),
		h.audit,
		audit,
		"oci manifest fetch started",
	); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *RegistryHandler) streamManifest(
	w http.ResponseWriter,
	r *http.Request,
	upstream domain.Upstream,
	audit proxyflow.AuditContext,
	artifact domain.ArtifactIdentity,
	tenantID, repo string,
) {
	// Allowed — fetch from upstream and stream to client.
	resp, err := h.upstream.FetchMetadata(r.Context(), upstream, artifact)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeOCIError(w, r, "MANIFEST_UNKNOWN", "manifest not found", http.StatusNotFound)
			return
		}
		audit.Artifact = artifact
		_ = proxyflow.RecordUpstreamFetchFailed(r.Context(), h.audit, audit, "oci manifest fetch failed", err)
		h.logger.Error("upstream manifest fetch failed",
			"error", err,
			"tenant_id", tenantID,
			"repo", repo,
		)
		writeOCIError(w, r, "MANIFEST_UNKNOWN", "upstream error", http.StatusBadGateway)
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
		writeOCIError(w, r, "UNAUTHORIZED", "tenant not identified", http.StatusUnauthorized)
		return
	}

	// Verify that a manifest-level allow decision exists for this repository.
	namespace, name := splitRepo(repo)
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: namespace,
		Name:      name,
	}
	requestID := proxyflow.RequestIDFromContext(r.Context())
	blobArtifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: namespace,
		Name:      name,
		Digest:    digest,
	}
	audit := proxyflow.AuditContext{
		TenantID:      tenant.ID,
		CorrelationID: requestID,
		Source:        "delivery/oci",
		Artifact:      blobArtifact,
		Operation:     "blob",
	}
	if err := proxyflow.RecordRequestReceived(
		r.Context(),
		h.audit,
		audit,
		r,
		"oci blob request received",
		map[string]any{
			"repository": repo,
			"digest":     digest,
		},
	); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}
	if !h.authorizeBlob(w, r, tenant.ID, repo, artifact, audit) {
		return
	}

	upstream, err := proxyflow.ResolveUpstream(r.Context(), h.upstreams, tenant.ID, domain.EcosystemOCI)
	if err != nil {
		writeOCIError(w, r, "NAME_UNKNOWN", "no OCI upstream configured", http.StatusNotFound)
		return
	}

	// Build a modified upstream with the repo path baked into the BaseURL
	// so the upstream client can construct the correct blob URL.
	blobUpstream := *upstream
	blobUpstream.BaseURL = strings.TrimRight(upstream.BaseURL, "/") + "/v2/" + repo
	audit.UpstreamID = upstream.ID
	if err := proxyflow.RecordSimpleRequestAllowed(
		r.Context(),
		h.audit,
		audit,
		"oci blob request allowed",
	); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}
	if err := proxyflow.RecordUpstreamFetchStarted(r.Context(), h.audit, audit, "oci blob fetch started"); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	h.streamBlob(w, r, blobUpstream, audit, tenant.ID, repo, digest)
}

func (h *RegistryHandler) authorizeBlob(
	w http.ResponseWriter,
	r *http.Request,
	tenantID, repo string,
	artifact domain.ArtifactIdentity,
	audit proxyflow.AuditContext,
) bool {
	allowed, err := h.access.HasRecentAllow(r.Context(), tenantID, artifact)
	if err != nil {
		h.logger.Error("failed to check manifest allow decision",
			"error", err,
			"tenant_id", tenantID,
			"repo", repo,
		)
		writeOCIError(w, r, "DENIED", "policy check error", http.StatusInternalServerError)
		return false
	}
	if allowed {
		return true
	}
	if err := proxyflow.RecordSimpleRequestDenied(
		r.Context(),
		h.audit,
		audit,
		"no manifest-level allow decision for this repository",
		"oci blob request denied",
	); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return false
	}
	writeOCIError(w, r, "DENIED", "no manifest-level allow decision for this repository", http.StatusForbidden)
	return false
}

func (h *RegistryHandler) streamBlob(
	w http.ResponseWriter,
	r *http.Request,
	upstream domain.Upstream,
	audit proxyflow.AuditContext,
	tenantID, repo, digest string,
) {
	resp, err := h.upstream.FetchContent(r.Context(), upstream, digest)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeOCIError(w, r, "BLOB_UNKNOWN", "blob not found", http.StatusNotFound)
			return
		}
		_ = proxyflow.RecordUpstreamFetchFailed(r.Context(), h.audit, audit, "oci blob fetch failed", err)
		h.logger.Error("upstream blob fetch failed",
			"error", err,
			"tenant_id", tenantID,
			"repo", repo,
		)
		writeOCIError(w, r, "BLOB_UNKNOWN", "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	streamResponse(w, resp)
}
