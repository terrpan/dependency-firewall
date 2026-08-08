package npm

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
	"github.com/danielterry/dependency-firewall/internal/delivery/proxyflow"
)

const (
	// npmAuditBulkPath is the registry-relative path npm POSTs its resolved
	// install set to after `npm install` / `npm ci` (unless --no-audit).
	npmAuditBulkPath = "-/npm/v1/security/advisories/bulk"

	// maxAuditBodyBytes bounds the accepted audit payload size.
	maxAuditBodyBytes = 8 << 20

	// snapshotProcessTimeout bounds the async root-inference work spawned for
	// one install snapshot.
	snapshotProcessTimeout = 2 * time.Minute
)

// routePost dispatches npm POST requests. Only the native audit bulk endpoint
// is supported; it doubles as the install-snapshot capture point.
func (h *RegistryHandler) routePost(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/npm/")
	if path == npmAuditBulkPath {
		h.handleAuditBulk(w, r)
		return
	}
	writeNPMError(w, "unsupported npm endpoint", http.StatusNotFound)
}

// handleAuditBulk captures the resolved install set npm reports through its
// audit request, schedules async dependency-graph root inference, and answers
// with an empty advisory set so the npm client proceeds normally.
func (h *RegistryHandler) handleAuditBulk(w http.ResponseWriter, r *http.Request) {
	tenant, ok := middleware.TenantFromContext(r.Context())
	if !ok {
		writeNPMError(w, "tenant not identified", http.StatusUnauthorized)
		return
	}

	payload, err := decodeAuditBulkPayload(r.Body, r.Header.Get("Content-Encoding"))
	if err != nil {
		h.logger.Warn("npm audit payload decode failed",
			"error", err,
			"tenant_id", tenant.ID,
			"content_encoding", r.Header.Get("Content-Encoding"),
		)
		writeNPMError(w, "invalid audit payload", http.StatusBadRequest)
		return
	}

	if h.snapshots != nil && len(payload) > 0 {
		upstream, err := proxyflow.ResolveUpstream(r.Context(), h.upstreams, tenant.ID, domain.EcosystemNPM)
		if err != nil {
			h.logger.Error("failed to look up npm upstream for install snapshot",
				"error", err,
				"tenant_id", tenant.ID,
			)
			writeNPMError(w, "no npm upstream configured", http.StatusNotFound)
			return
		}
		snapshot := domain.NPMInstallSnapshot{
			TenantID:   tenant.ID,
			Upstream:   *upstream,
			Packages:   auditBulkPackages(payload),
			ObservedAt: time.Now().UTC(),
		}
		h.logger.Info("npm install snapshot received",
			"tenant_id", tenant.ID,
			"upstream_id", upstream.ID,
			"package_count", len(snapshot.Packages),
		)
		go h.processSnapshot(r.Context(), snapshot)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// processSnapshot runs root inference detached from the request lifecycle.
func (h *RegistryHandler) processSnapshot(ctx context.Context, snapshot domain.NPMInstallSnapshot) {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), snapshotProcessTimeout)
	defer cancel()
	if _, err := h.snapshots.ProcessSnapshot(detached, snapshot); err != nil {
		h.logger.Error("npm install snapshot processing failed",
			"error", err,
			"tenant_id", snapshot.TenantID,
		)
	}
}

// decodeAuditBulkPayload parses the npm bulk advisory request body, a map of
// package name to the list of resolved versions. npm compresses the request
// body, so gzip content encoding is decoded transparently.
func decodeAuditBulkPayload(body io.Reader, contentEncoding string) (map[string][]string, error) {
	reader := io.LimitReader(body, maxAuditBodyBytes)
	if strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") {
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	payload := make(map[string][]string)
	if err := json.NewDecoder(reader).Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func auditBulkPackages(payload map[string][]string) []domain.ArtifactIdentity {
	packages := make([]domain.ArtifactIdentity, 0, len(payload))
	for name, versions := range payload {
		for _, version := range versions {
			packages = append(packages, domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      name,
				Version:   version,
			})
		}
	}
	return packages
}
