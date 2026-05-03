package health

import (
	"encoding/json"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// Handler serves plain HTTP health responses for non-Huma service entrypoints.
type Handler struct {
	healthService *service.HealthService
}

// NewHandler creates a new Handler.
func NewHandler(healthService *service.HealthService) *Handler {
	return &Handler{healthService: healthService}
}

// RegisterRoutes registers health routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.handleHealthCheck)
}

func (h *Handler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	status := h.healthService.CheckHealth(r.Context())

	httpStatus := http.StatusOK
	if status.Status != "healthy" {
		httpStatus = http.StatusServiceUnavailable
	}

	writeJSON(w, healthResponseFromStatus(status), httpStatus)
}

type healthResponse struct {
	Status       string                        `json:"status"`
	ServiceName  string                        `json:"service_name"`
	Version      string                        `json:"version"`
	Commit       string                        `json:"commit"`
	BuildTime    string                        `json:"build_time"`
	GoVersion    string                        `json:"go_version"`
	OS           string                        `json:"os"`
	Arch         string                        `json:"arch"`
	Timestamp    string                        `json:"timestamp"`
	Dependencies map[string]dependencyResponse `json:"dependencies"`
	Bundle       *componentResponse            `json:"bundle,omitempty"`
	Proxy        *componentResponse            `json:"proxy,omitempty"`
}

type dependencyResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Duration  int64  `json:"duration_ms"`
	Timestamp string `json:"timestamp"`
}

type componentResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"timestamp"`
}

func healthResponseFromStatus(status service.HealthStatus) healthResponse {
	dependencies := make(map[string]dependencyResponse, len(status.Dependencies))
	for name, dep := range status.Dependencies {
		dependencies[name] = dependencyResponse{
			Status:    dep.Status,
			Message:   dep.Message,
			Duration:  dep.Duration,
			Timestamp: dep.Timestamp.Format(timeLayout),
		}
	}

	response := healthResponse{
		Status:       status.Status,
		ServiceName:  status.ServiceName,
		Version:      status.Version,
		Commit:       status.Commit,
		BuildTime:    status.BuildTime,
		GoVersion:    status.GoVersion,
		OS:           status.OS,
		Arch:         status.Arch,
		Timestamp:    status.Timestamp.Format(timeLayout),
		Dependencies: dependencies,
	}

	if status.Proxy != nil {
		response.Proxy = &componentResponse{
			Status:    status.Proxy.Status,
			Message:   status.Proxy.Message,
			Timestamp: status.Proxy.Timestamp.Format(timeLayout),
		}
	}
	if status.Bundle != nil {
		response.Bundle = &componentResponse{
			Status:    status.Bundle.Status,
			Message:   status.Bundle.Message,
			Timestamp: status.Bundle.Timestamp.Format(timeLayout),
		}
	}

	return response
}

const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

func writeJSON(w http.ResponseWriter, value any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
