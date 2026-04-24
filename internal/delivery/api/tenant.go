package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// TenantHandler handles tenant CRUD endpoints.
type TenantHandler struct {
	tenants *service.TenantService
	logger  *slog.Logger
}

// NewTenantHandler creates a new TenantHandler.
func NewTenantHandler(tenants *service.TenantService, logger *slog.Logger) *TenantHandler {
	return &TenantHandler{tenants: tenants, logger: logger}
}

// RegisterRoutes registers tenant API routes on the given mux.
func (h *TenantHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/tenants", h.create)
	mux.HandleFunc("GET /api/v1/tenants", h.list)
	mux.HandleFunc("GET /api/v1/tenants/{id}", h.get)
	mux.HandleFunc("PUT /api/v1/tenants/{id}", h.update)
	mux.HandleFunc("DELETE /api/v1/tenants/{id}", h.delete)
}

type createTenantRequest struct {
	Name string `json:"name" validate:"notblank"`
}

func (h *TenantHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	tenant := &domain.Tenant{Name: req.Name}
	if err := h.tenants.Create(r.Context(), tenant); err != nil {
		if errors.Is(err, domain.ErrTenantNameConflict) {
			writeError(w, http.StatusConflict, "tenant name already exists")
			return
		}
		h.logger.Error("creating tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create tenant")
		return
	}
	writeJSON(w, http.StatusCreated, toTenantResponse(tenant))
}

func (h *TenantHandler) list(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.tenants.List(r.Context())
	if err != nil {
		h.logger.Error("listing tenants", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list tenants")
		return
	}
	writeJSON(w, http.StatusOK, toTenantsResponse(tenants))
}

func (h *TenantHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenant, err := h.tenants.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		h.logger.Error("getting tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get tenant")
		return
	}
	writeJSON(w, http.StatusOK, toTenantResponse(tenant))
}

func (h *TenantHandler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req createTenantRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	tenant := &domain.Tenant{ID: id, Name: req.Name}
	if err := h.tenants.Update(r.Context(), tenant); err != nil {
		if errors.Is(err, domain.ErrTenantNameConflict) {
			writeError(w, http.StatusConflict, "tenant name already exists")
			return
		}
		if errors.Is(err, domain.ErrTenantNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		h.logger.Error("updating tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update tenant")
		return
	}
	writeJSON(w, http.StatusOK, toTenantResponse(tenant))
}

func (h *TenantHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.tenants.Delete(r.Context(), id); err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		h.logger.Error("deleting tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete tenant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
