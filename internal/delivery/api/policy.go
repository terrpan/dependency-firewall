package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// PolicyHandler handles policy CRUD and import endpoints.
type PolicyHandler struct {
	repo   port.PolicyRepository
	logger *slog.Logger
}

// NewPolicyHandler creates a new PolicyHandler.
func NewPolicyHandler(repo port.PolicyRepository, logger *slog.Logger) *PolicyHandler {
	return &PolicyHandler{repo: repo, logger: logger}
}

// RegisterRoutes registers policy API routes on the given mux.
func (h *PolicyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/policies/import", h.importYAML)
	mux.HandleFunc("POST /api/v1/policies", h.create)
	mux.HandleFunc("GET /api/v1/policies", h.list)
	mux.HandleFunc("GET /api/v1/policies/{id}", h.get)
	mux.HandleFunc("PUT /api/v1/policies/{id}", h.update)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", h.delete)
}

func (h *PolicyHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var p domain.Policy
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.TenantID = tenantID

	if err := h.repo.Create(r.Context(), &p); err != nil {
		h.logger.Error("creating policy", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}
	writeJSON(w, http.StatusCreated, toPolicyResponse(&p))
}

func (h *PolicyHandler) importYAML(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	pf, err := policy.ParseFile(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Override tenant_id from header.
	pf.TenantID = tenantID

	policies, err := policy.ToDomainPolicies(pf)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	for i := range policies {
		if err := h.repo.Create(r.Context(), &policies[i]); err != nil {
			h.logger.Error("importing policy", "error", err, "policy", policies[i].Name)
			writeError(w, http.StatusInternalServerError, "failed to import policies")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]int{"imported": len(policies)})
}

func (h *PolicyHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies, err := h.repo.ListByTenant(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("listing policies", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}
	writeJSON(w, http.StatusOK, toPoliciesResponse(policies))
}

func (h *PolicyHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	p, err := h.repo.GetByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
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
	var p domain.Policy
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.ID = id
	p.TenantID = tenantID

	if err := h.repo.Update(r.Context(), &p); err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		h.logger.Error("updating policy", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}
	writeJSON(w, http.StatusOK, toPolicyResponse(&p))
}

func (h *PolicyHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	if err := h.repo.Delete(r.Context(), tenantID, id); err != nil {
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
