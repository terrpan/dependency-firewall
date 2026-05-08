// Package oci implements OCI registry protocol handlers.
package oci

import (
	"context"
	"errors"
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
	audits ...*service.AuditService,
) *RegistryHandler {
	var audit *service.AuditService
	if len(audits) > 0 {
		audit = audits[0]
	}
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

	upstream, err := h.resolveUpstream(r.Context(), tenant.ID)
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

	req := domain.AccessRequest{
		TenantID:  tenant.ID,
		RequestID: requestIDFromContext(r.Context()),
		Artifact:  artifact,
		Upstream:  *upstream,
		Timestamp: time.Now(),
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventProxyRequestReceived,
		Source:        "delivery/oci",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Message:       "oci manifest request received",
		Payload: map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"remote_addr": r.RemoteAddr,
			"operation":   "manifest",
			"reference":   reference,
			"repository":  repo,
		},
	}); err != nil {
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

	if decision.Outcome == domain.DecisionDeny {
		if err := h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventRequestDenied,
			Source:        "delivery/oci",
			EntityType:    "decision",
			EntityID:      decision.ID,
			UpstreamID:    upstream.ID,
			PolicyID:      decision.PolicyID,
			Outcome:       decision.Outcome,
			Artifact:      decision.Artifact,
			Message:       "oci manifest request denied",
			Payload: map[string]any{
				"reason":    decision.Reason,
				"operation": "manifest",
			},
		}); err != nil {
			writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
			return
		}
		writeOCIError(w, r, "DENIED", "policy violation: "+decision.Reason, http.StatusForbidden)
		return
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventRequestAllowed,
		Source:        "delivery/oci",
		EntityType:    "decision",
		EntityID:      decision.ID,
		UpstreamID:    upstream.ID,
		PolicyID:      decision.PolicyID,
		Outcome:       decision.Outcome,
		Artifact:      decision.Artifact,
		Message:       "oci manifest request allowed",
		Payload: map[string]any{
			"operation": "manifest",
			"warnings":  decision.Warnings,
		},
	}); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventUpstreamFetchStarted,
		Source:        "delivery/oci",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Message:       "oci manifest fetch started",
		Payload: map[string]any{
			"operation": "manifest",
		},
	}); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	// Allowed — fetch from upstream and stream to client.
	resp, err := h.upstream.FetchMetadata(r.Context(), *upstream, decision.Artifact)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeOCIError(w, r, "MANIFEST_UNKNOWN", "manifest not found", http.StatusNotFound)
			return
		}
		_ = h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventUpstreamFetchFailed,
			Source:        "delivery/oci",
			UpstreamID:    upstream.ID,
			Artifact:      decision.Artifact,
			Message:       "oci manifest fetch failed",
			Payload: map[string]any{
				"operation": "manifest",
				"error":     err.Error(),
			},
		})
		h.logger.Error("upstream manifest fetch failed",
			"error", err,
			"tenant_id", tenant.ID,
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
	requestID := requestIDFromContext(r.Context())
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: requestID,
		EventType:     domain.AuditEventProxyRequestReceived,
		Source:        "delivery/oci",
		UpstreamID:    "",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Namespace: namespace,
			Name:      name,
			Digest:    digest,
		},
		Message: "oci blob request received",
		Payload: map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"remote_addr": r.RemoteAddr,
			"operation":   "blob",
			"repository":  repo,
			"digest":      digest,
		},
	}); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}
	allowed, err := h.access.HasRecentAllow(r.Context(), tenant.ID, artifact)
	if err != nil {
		h.logger.Error("failed to check manifest allow decision",
			"error", err,
			"tenant_id", tenant.ID,
			"repo", repo,
		)
		writeOCIError(w, r, "DENIED", "policy check error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		if err := h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: requestID,
			EventType:     domain.AuditEventRequestDenied,
			Source:        "delivery/oci",
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemOCI,
				Namespace: namespace,
				Name:      name,
				Digest:    digest,
			},
			Message: "oci blob request denied",
			Payload: map[string]any{
				"reason":    "no manifest-level allow decision for this repository",
				"operation": "blob",
			},
		}); err != nil {
			writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
			return
		}
		writeOCIError(w, r, "DENIED", "no manifest-level allow decision for this repository", http.StatusForbidden)
		return
	}

	upstream, err := h.resolveUpstream(r.Context(), tenant.ID)
	if err != nil {
		writeOCIError(w, r, "NAME_UNKNOWN", "no OCI upstream configured", http.StatusNotFound)
		return
	}

	// Build a modified upstream with the repo path baked into the BaseURL
	// so the upstream client can construct the correct blob URL.
	blobUpstream := *upstream
	blobUpstream.BaseURL = strings.TrimRight(upstream.BaseURL, "/") + "/v2/" + repo
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: requestID,
		EventType:     domain.AuditEventRequestAllowed,
		Source:        "delivery/oci",
		UpstreamID:    upstream.ID,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Namespace: namespace,
			Name:      name,
			Digest:    digest,
		},
		Message: "oci blob request allowed",
		Payload: map[string]any{
			"operation": "blob",
		},
	}); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: requestID,
		EventType:     domain.AuditEventUpstreamFetchStarted,
		Source:        "delivery/oci",
		UpstreamID:    upstream.ID,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Namespace: namespace,
			Name:      name,
			Digest:    digest,
		},
		Message: "oci blob fetch started",
		Payload: map[string]any{
			"operation": "blob",
		},
	}); err != nil {
		writeOCIError(w, r, "DENIED", "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	resp, err := h.upstream.FetchContent(r.Context(), blobUpstream, digest)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeOCIError(w, r, "BLOB_UNKNOWN", "blob not found", http.StatusNotFound)
			return
		}
		_ = h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: requestID,
			EventType:     domain.AuditEventUpstreamFetchFailed,
			Source:        "delivery/oci",
			UpstreamID:    upstream.ID,
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemOCI,
				Namespace: namespace,
				Name:      name,
				Digest:    digest,
			},
			Message: "oci blob fetch failed",
			Payload: map[string]any{
				"operation": "blob",
				"error":     err.Error(),
			},
		})
		h.logger.Error("upstream blob fetch failed",
			"error", err,
			"tenant_id", tenant.ID,
			"repo", repo,
		)
		writeOCIError(w, r, "BLOB_UNKNOWN", "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	streamResponse(w, resp)
}

func (h *RegistryHandler) recordAudit(ctx context.Context, event domain.AuditEvent) error {
	if h.audit == nil {
		return nil
	}
	return h.audit.Record(ctx, event)
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := middleware.RequestIDFromContext(ctx)
	return requestID
}

func (h *RegistryHandler) resolveUpstream(ctx context.Context, tenantID string) (*domain.Upstream, error) {
	if upstreamID, ok := middleware.UpstreamIDFromContext(ctx); ok && upstreamID != "" {
		upstream, err := h.upstreams.GetByID(ctx, tenantID, upstreamID)
		if err != nil {
			return nil, err
		}
		if upstream.Ecosystem != domain.EcosystemOCI {
			return nil, domain.ErrUpstreamNotFound
		}
		return upstream, nil
	}

	return h.upstreams.GetByEcosystem(ctx, tenantID, domain.EcosystemOCI)
}
