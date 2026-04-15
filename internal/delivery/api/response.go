// Package api implements the control plane REST API handlers.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Response DTOs with JSON tags for lowercase serialization.

type TenantResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UpstreamResponse struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	BaseURL   string `json:"base_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PolicyResponse struct {
	ID        string         `json:"id"`
	TenantID  string         `json:"tenant_id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Action    string         `json:"action"`
	Config    map[string]any `json:"config"`
	Priority  int            `json:"priority"`
	Enabled   bool           `json:"enabled"`
	Version   int            `json:"version"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type DecisionResponse struct {
	ID          string                   `json:"id"`
	TenantID    string                   `json:"tenant_id"`
	Artifact    ArtifactIdentityResponse `json:"artifact"`
	Outcome     string                   `json:"outcome"`
	PolicyID    string                   `json:"policy_id"`
	Reason      string                   `json:"reason"`
	Reasons     []EvaluationReasonResponse `json:"reasons"`
	CachedAt    *time.Time               `json:"cached_at,omitempty"`
	EvaluatedAt time.Time                `json:"evaluated_at"`
}

type ArtifactIdentityResponse struct {
	Ecosystem string `json:"ecosystem"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type EvaluationReasonResponse struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	Message    string `json:"message"`
}

// Converters to transform domain models to response DTOs.

func toTenantResponse(t *domain.Tenant) *TenantResponse {
	return &TenantResponse{
		ID:        t.ID,
		Name:      t.Name,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

func toTenantsResponse(tenants []domain.Tenant) []*TenantResponse {
	result := make([]*TenantResponse, len(tenants))
	for i := range tenants {
		result[i] = toTenantResponse(&tenants[i])
	}
	return result
}

func toUpstreamResponse(u *domain.Upstream) *UpstreamResponse {
	return &UpstreamResponse{
		ID:        u.ID,
		TenantID:  u.TenantID,
		Name:      u.Name,
		Ecosystem: string(u.Ecosystem),
		BaseURL:   u.BaseURL,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

func toUpstreamsResponse(upstreams []domain.Upstream) []*UpstreamResponse {
	result := make([]*UpstreamResponse, len(upstreams))
	for i := range upstreams {
		result[i] = toUpstreamResponse(&upstreams[i])
	}
	return result
}

func toPolicyResponse(p *domain.Policy) *PolicyResponse {
	return &PolicyResponse{
		ID:        p.ID,
		TenantID:  p.TenantID,
		Name:      p.Name,
		Type:      string(p.Type),
		Action:    string(p.Action),
		Config:    p.Config,
		Priority:  p.Priority,
		Enabled:   p.Enabled,
		Version:   p.Version,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

func toPoliciesResponse(policies []domain.Policy) []*PolicyResponse {
	result := make([]*PolicyResponse, len(policies))
	for i := range policies {
		result[i] = toPolicyResponse(&policies[i])
	}
	return result
}

func toDecisionResponse(d *domain.Decision) *DecisionResponse {
	artifact := ArtifactIdentityResponse{
		Ecosystem: string(d.Artifact.Ecosystem),
		Namespace: d.Artifact.Namespace,
		Name:      d.Artifact.Name,
		Version:   d.Artifact.Version,
		Digest:    d.Artifact.Digest,
	}

	reasons := make([]EvaluationReasonResponse, len(d.Reasons))
	for i, r := range d.Reasons {
		reasons[i] = EvaluationReasonResponse{
			PolicyID:   r.PolicyID,
			PolicyName: r.PolicyName,
			Category:   string(r.Category),
			Action:     string(r.Action),
			Message:    r.Message,
		}
	}

	return &DecisionResponse{
		ID:          d.ID,
		TenantID:    d.TenantID,
		Artifact:    artifact,
		Outcome:     string(d.Outcome),
		PolicyID:    d.PolicyID,
		Reason:      d.Reason,
		Reasons:     reasons,
		CachedAt:    d.CachedAt,
		EvaluatedAt: d.EvaluatedAt,
	}
}

func toDecisionsResponse(decisions []domain.Decision) []*DecisionResponse {
	result := make([]*DecisionResponse, len(decisions))
	for i := range decisions {
		result[i] = toDecisionResponse(&decisions[i])
	}
	return result
}

// HTTP helpers.

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "encoding response", http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func readJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func tenantIDFromHeader(r *http.Request) (string, error) {
	id := r.Header.Get("X-Tenant-ID")
	if id == "" {
		return "", fmt.Errorf("missing X-Tenant-ID header")
	}
	return id, nil
}
