package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

type healthResponse struct {
	Status       string                        `json:"status"`
	ServiceName  string                        `json:"service_name"`
	Version      string                        `json:"version"`
	Commit       string                        `json:"commit,omitempty"`
	BuildTime    string                        `json:"build_time,omitempty"`
	GoVersion    string                        `json:"go_version"`
	OS           string                        `json:"os"`
	Arch         string                        `json:"arch"`
	Timestamp    time.Time                     `json:"timestamp"`
	Dependencies map[string]dependencyResponse `json:"dependencies"`
	Bundle       *componentResponse            `json:"bundle,omitempty"`
	Proxy        *componentResponse            `json:"proxy,omitempty"`
}

type dependencyResponse struct {
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	Duration  int64     `json:"duration_ms"`
	Timestamp time.Time `json:"timestamp"`
}

type componentResponse struct {
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

func toHealthResponse(status service.HealthStatus) healthResponse {
	dependencies := make(map[string]dependencyResponse, len(status.Dependencies))
	for name, dep := range status.Dependencies {
		dependencies[name] = dependencyResponse{
			Status:    dep.Status,
			Message:   dep.Message,
			Duration:  dep.Duration,
			Timestamp: dep.Timestamp,
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
		Timestamp:    status.Timestamp,
		Dependencies: dependencies,
	}

	if status.Proxy != nil {
		response.Proxy = &componentResponse{
			Status:    status.Proxy.Status,
			Message:   status.Proxy.Message,
			Timestamp: status.Proxy.Timestamp,
		}
	}
	if status.Bundle != nil {
		response.Bundle = &componentResponse{
			Status:    status.Bundle.Status,
			Message:   status.Bundle.Message,
			Timestamp: status.Bundle.Timestamp,
		}
	}

	return response
}
