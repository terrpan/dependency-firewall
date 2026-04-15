package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// UpstreamHandler handles upstream registry CRUD endpoints.
type UpstreamHandler struct {
	repo   port.UpstreamRepository
	logger *slog.Logger
}

// NewUpstreamHandler creates a new UpstreamHandler.
func NewUpstreamHandler(repo port.UpstreamRepository, logger *slog.Logger) *UpstreamHandler {
	return &UpstreamHandler{repo: repo, logger: logger}
}

// RegisterRoutes registers upstream API routes on the given mux.
func (h *UpstreamHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/upstreams", h.create)
	mux.HandleFunc("GET /api/v1/upstreams", h.list)
	mux.HandleFunc("GET /api/v1/upstreams/{id}", h.get)
	mux.HandleFunc("PUT /api/v1/upstreams/{id}", h.update)
	mux.HandleFunc("DELETE /api/v1/upstreams/{id}", h.delete)
}

type createUpstreamRequest struct {
	Name      string              `json:"name"`
	Ecosystem domain.EcosystemType `json:"ecosystem"`
	BaseURL   string              `json:"base_url"`
}

func (h *UpstreamHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createUpstreamRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	upstream := &domain.Upstream{
		TenantID:  tenantID,
		Name:      req.Name,
		Ecosystem: req.Ecosystem,
		BaseURL:   req.BaseURL,
	}
	if err := h.repo.Create(r.Context(), upstream); err != nil {
		h.logger.Error("creating upstream", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create upstream")
		return
	}
	writeJSON(w, http.StatusCreated, upstream)
}

func (h *UpstreamHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	upstreams, err := h.repo.ListByTenant(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("listing upstreams", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list upstreams")
		return
	}
	writeJSON(w, http.StatusOK, upstreams)
}

func (h *UpstreamHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	u, err := h.repo.GetByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			writeError(w, http.StatusNotFound, "upstream not found")
			return
		}
		h.logger.Error("getting upstream", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get upstream")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *UpstreamHandler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	var req createUpstreamRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	upstream := &domain.Upstream{
		ID:        id,
		TenantID:  tenantID,
		Name:      req.Name,
		Ecosystem: req.Ecosystem,
		BaseURL:   req.BaseURL,
	}
	if err := h.repo.Update(r.Context(), upstream); err != nil {
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			writeError(w, http.StatusNotFound, "upstream not found")
			return
		}
		h.logger.Error("updating upstream", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update upstream")
		return
	}
	writeJSON(w, http.StatusOK, upstream)
}

func (h *UpstreamHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDFromHeader(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := r.PathValue("id")
	if err := h.repo.Delete(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			writeError(w, http.StatusNotFound, "upstream not found")
			return
		}
		h.logger.Error("deleting upstream", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete upstream")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
