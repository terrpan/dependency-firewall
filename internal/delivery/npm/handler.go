// Package npm implements npm registry protocol handlers.
package npm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
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
	audit     *service.AuditService
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
		RequestID: requestIDFromContext(r.Context()),
		Artifact:  artifact,
		Upstream:  *upstream,
		Timestamp: time.Now(),
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventProxyRequestReceived,
		Source:        "delivery/npm",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Message:       "npm metadata request received",
		Payload: map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"remote_addr": r.RemoteAddr,
			"operation":   "metadata",
		},
	}); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
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
		if err := h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventRequestDenied,
			Source:        "delivery/npm",
			EntityType:    "decision",
			EntityID:      decision.ID,
			UpstreamID:    upstream.ID,
			PolicyID:      decision.PolicyID,
			Outcome:       decision.Outcome,
			Artifact:      decision.Artifact,
			Message:       "npm metadata request denied",
			Payload: map[string]any{
				"reason":    decision.Reason,
				"operation": "metadata",
			},
		}); err != nil {
			writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
			return
		}
		writeNPMError(w, "policy violation: "+decision.Reason, http.StatusForbidden)
		return
	}

	addWarningHeaders(w, decision)
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventRequestAllowed,
		Source:        "delivery/npm",
		EntityType:    "decision",
		EntityID:      decision.ID,
		UpstreamID:    upstream.ID,
		PolicyID:      decision.PolicyID,
		Outcome:       decision.Outcome,
		Artifact:      decision.Artifact,
		Message:       "npm metadata request allowed",
		Payload: map[string]any{
			"operation": "metadata",
			"warnings":  decision.Warnings,
		},
	}); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventUpstreamFetchStarted,
		Source:        "delivery/npm",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Message:       "npm upstream metadata fetch started",
		Payload: map[string]any{
			"operation": "metadata",
		},
	}); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	resp, err := h.upstream.FetchMetadata(r.Context(), *upstream, artifact)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeNPMError(w, "package not found", http.StatusNotFound)
			return
		}
		_ = h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventUpstreamFetchFailed,
			Source:        "delivery/npm",
			UpstreamID:    upstream.ID,
			Artifact:      artifact,
			Message:       "npm upstream metadata fetch failed",
			Payload: map[string]any{
				"operation": "metadata",
				"error":     err.Error(),
			},
		})
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
		RequestID: requestIDFromContext(r.Context()),
		Artifact:  artifact,
		Upstream:  *upstream,
		Timestamp: time.Now(),
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventProxyRequestReceived,
		Source:        "delivery/npm",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Message:       "npm tarball request received",
		Payload: map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"remote_addr": r.RemoteAddr,
			"operation":   "tarball",
		},
	}); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
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
		if err := h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventRequestDenied,
			Source:        "delivery/npm",
			EntityType:    "decision",
			EntityID:      decision.ID,
			UpstreamID:    upstream.ID,
			PolicyID:      decision.PolicyID,
			Outcome:       decision.Outcome,
			Artifact:      decision.Artifact,
			Message:       "npm tarball request denied",
			Payload: map[string]any{
				"reason":    decision.Reason,
				"operation": "tarball",
			},
		}); err != nil {
			writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
			return
		}
		writeNPMError(w, "policy violation: "+decision.Reason, http.StatusForbidden)
		return
	}

	addWarningHeaders(w, decision)
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventRequestAllowed,
		Source:        "delivery/npm",
		EntityType:    "decision",
		EntityID:      decision.ID,
		UpstreamID:    upstream.ID,
		PolicyID:      decision.PolicyID,
		Outcome:       decision.Outcome,
		Artifact:      decision.Artifact,
		Message:       "npm tarball request allowed",
		Payload: map[string]any{
			"operation": "tarball",
			"warnings":  decision.Warnings,
		},
	}); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
	}
	if err := h.recordAudit(r.Context(), domain.AuditEvent{
		TenantID:      tenant.ID,
		CorrelationID: req.RequestID,
		EventType:     domain.AuditEventUpstreamFetchStarted,
		Source:        "delivery/npm",
		UpstreamID:    upstream.ID,
		Artifact:      artifact,
		Message:       "npm upstream tarball fetch started",
		Payload: map[string]any{
			"operation": "tarball",
		},
	}); err != nil {
		writeNPMError(w, "audit logging unavailable", http.StatusInternalServerError)
		return
	}

	// Use the tarball filename as the digest/identifier for the blob fetch.
	tarball := tarballFilename(name, version)
	resp, err := h.upstream.FetchContent(r.Context(), *upstream, tarball)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			writeNPMError(w, "tarball not found", http.StatusNotFound)
			return
		}
		_ = h.recordAudit(r.Context(), domain.AuditEvent{
			TenantID:      tenant.ID,
			CorrelationID: req.RequestID,
			EventType:     domain.AuditEventUpstreamFetchFailed,
			Source:        "delivery/npm",
			UpstreamID:    upstream.ID,
			Artifact:      artifact,
			Message:       "npm upstream tarball fetch failed",
			Payload: map[string]any{
				"operation": "tarball",
				"error":     err.Error(),
			},
		})
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
		if upstream.Ecosystem != domain.EcosystemNPM {
			return nil, domain.ErrUpstreamNotFound
		}
		return upstream, nil
	}

	return h.upstreams.GetByEcosystem(ctx, tenantID, domain.EcosystemNPM)
}
