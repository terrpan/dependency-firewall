package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// PolicyHandler handles policy CRUD and import endpoints.
type PolicyHandler struct {
	policies *service.PolicyService
	logger   *slog.Logger
}

// NewPolicyHandler creates a new PolicyHandler.
func NewPolicyHandler(policies *service.PolicyService, logger *slog.Logger) *PolicyHandler {
	return &PolicyHandler{policies: policies, logger: logger}
}

type policyRequest struct {
	Name          string              `json:"name" validate:"notblank"`
	Type          domain.PolicyType   `json:"type" validate:"required,oneof=cvss_threshold minimum_age maximum_age block_mutable_tag license license_allowlist allowlist blocklist"`
	Action        domain.PolicyAction `json:"action" validate:"required,oneof=allow deny"`
	SchemaVersion int                 `json:"schema_version" validate:"required,gte=1"`
	Config        json.RawMessage     `json:"config" validate:"required"`
	Priority      int                 `json:"priority"`
	Enabled       bool                `json:"enabled"`
}

type policyRollbackRequest struct {
	Version int `json:"version" validate:"required,gte=1"`
}

// RegisterRoutes registers policy API routes on the given mux.
func (h *PolicyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/policy-types", h.listTypes)
	mux.HandleFunc("POST /api/v1/policies/import", h.importPolicies)
	mux.HandleFunc("POST /api/v1/policies", h.create)
	mux.HandleFunc("GET /api/v1/policies", h.list)
	mux.HandleFunc("GET /api/v1/policies/{id}/versions", h.listVersions)
	mux.HandleFunc("POST /api/v1/policies/{id}/rollback", h.rollback)
	mux.HandleFunc("GET /api/v1/policies/{id}", h.get)
	mux.HandleFunc("PUT /api/v1/policies/{id}", h.update)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", h.delete)
}

func (h *PolicyHandler) listTypes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, toPolicyTypesResponse(h.policies.ListTypes()))
}

func (h *PolicyHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req policyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	config, err := corepolicy.DecodeConfigJSON(req.Type, req.SchemaVersion, req.Config)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := &domain.Policy{
		TenantID:      tenantID,
		Name:          req.Name,
		Type:          req.Type,
		Action:        req.Action,
		SchemaVersion: req.SchemaVersion,
		Config:        config,
		Priority:      req.Priority,
		Enabled:       req.Enabled,
	}

	if err := h.policies.Create(r.Context(), p); err != nil {
		if errors.Is(err, domain.ErrInvalidPolicy) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, domain.ErrPolicyNameConflict) {
			writeError(w, http.StatusConflict, "policy name already exists")
			return
		}
		h.logger.Error("creating policy", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}
	writeJSON(w, http.StatusCreated, toPolicyResponse(p))
}

func (h *PolicyHandler) importPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	mediaType, err := parseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if mediaType != "" && !isSupportedPolicyImportContentType(mediaType) {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported Content-Type for policy import")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	count, err := h.policies.ImportPolicies(r.Context(), tenantID, body)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidPolicy) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, domain.ErrPolicyNameConflict) {
			writeError(w, http.StatusConflict, "policy name already exists")
			return
		}
		h.logger.Error("importing policies", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to import policies")
		return
	}

	writeJSON(w, http.StatusOK, map[string]int{"imported": count})
}

func (h *PolicyHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.policies.ListByTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			writeError(w, http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
			return
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			writeError(w, http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
			return
		}
		h.logger.Error("listing policies", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}
	writeJSON(w, http.StatusOK, toPoliciesResponse(policies))
}

func (h *PolicyHandler) listVersions(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	versions, err := h.policies.ListVersions(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			writeError(w, http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
			return
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			writeError(w, http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
			return
		}
		h.logger.Error("listing policy versions", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list policy versions")
		return
	}

	writeJSON(w, http.StatusOK, toPolicyVersionsResponse(versions))
}

func (h *PolicyHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	p, err := h.policies.GetByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			writeError(w, http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
			return
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			writeError(w, http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
			return
		}
		h.logger.Error("getting policy", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get policy")
		return
	}
	writeJSON(w, http.StatusOK, toPolicyResponse(p))
}

func (h *PolicyHandler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	var req policyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	config, err := corepolicy.DecodeConfigJSON(req.Type, req.SchemaVersion, req.Config)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := &domain.Policy{
		ID:            id,
		TenantID:      tenantID,
		Name:          req.Name,
		Type:          req.Type,
		Action:        req.Action,
		SchemaVersion: req.SchemaVersion,
		Config:        config,
		Priority:      req.Priority,
		Enabled:       req.Enabled,
	}

	if err := h.policies.Update(r.Context(), p); err != nil {
		if errors.Is(err, domain.ErrInvalidPolicy) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, domain.ErrPolicyNameConflict) {
			writeError(w, http.StatusConflict, "policy name already exists")
			return
		}
		if errors.Is(err, domain.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		h.logger.Error("updating policy", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}
	writeJSON(w, http.StatusOK, toPolicyResponse(p))
}

func (h *PolicyHandler) rollback(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req policyRollbackRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	p, err := h.policies.RollbackToVersion(r.Context(), tenantID, r.PathValue("id"), req.Version)
	if err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		if errors.Is(err, domain.ErrPolicyVersionNotFound) {
			writeError(w, http.StatusNotFound, "policy version not found")
			return
		}
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			writeError(w, http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
			return
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			writeError(w, http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
			return
		}
		if errors.Is(err, domain.ErrInvalidPolicy) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logger.Error("rolling back policy", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to rollback policy")
		return
	}

	writeJSON(w, http.StatusOK, toPolicyResponse(p))
}

func (h *PolicyHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	if err := h.policies.Delete(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		h.logger.Error("deleting policy", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseMediaType(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", errors.New("invalid Content-Type header")
	}
	return mediaType, nil
}

func isSupportedPolicyImportContentType(mediaType string) bool {
	switch mediaType {
	case "application/json", "application/x-yaml", "application/yaml", "text/yaml", "text/x-yaml":
		return true
	default:
		return false
	}
}
