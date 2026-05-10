// Package api implements the control plane REST API handlers.
package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// Response DTOs with JSON tags for lowercase serialization.

type TenantResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UpstreamResponse struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	Ecosystem            string               `json:"ecosystem"`
	BaseURL              string               `json:"base_url"`
	Capabilities         []string             `json:"capabilities"`
	SupportedPolicyTypes []string             `json:"supported_policy_types"`
	Auth                 UpstreamAuthResponse `json:"auth"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at"`
}

type UpstreamAuthResponse struct {
	Type       string     `json:"type"`
	Configured bool       `json:"configured"`
	Username   string     `json:"username,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

type PolicyResponse struct {
	ID            string    `json:"id"`
	UpstreamID    string    `json:"upstream_id,omitempty"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Action        string    `json:"action"`
	SchemaVersion int       `json:"schema_version"`
	Config        any       `json:"config"`
	Priority      int       `json:"priority"`
	Enabled       bool      `json:"enabled"`
	Version       int       `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type PolicyVersionResponse struct {
	Version       int       `json:"version"`
	UpstreamID    string    `json:"upstream_id,omitempty"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Action        string    `json:"action"`
	SchemaVersion int       `json:"schema_version"`
	Config        any       `json:"config"`
	Priority      int       `json:"priority"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

type PolicyTypeResponse struct {
	Type                    string   `json:"type"`
	Summary                 string   `json:"summary"`
	Description             string   `json:"description"`
	Help                    string   `json:"help"`
	CurrentSchemaVersion    int      `json:"current_schema_version"`
	SupportedSchemaVersions []int    `json:"supported_schema_versions"`
	SupportedActions        []string `json:"supported_actions"`
	SupportedEcosystems     []string `json:"supported_ecosystems"`
	RequiredCapabilities    []string `json:"required_capabilities"`
	Example                 string   `json:"example"`
}

type DecisionResponse struct {
	ID          string                     `json:"id"`
	Artifact    ArtifactIdentityResponse   `json:"artifact"`
	Outcome     string                     `json:"outcome"`
	PolicyID    string                     `json:"policy_id"`
	PolicyHash  string                     `json:"policy_hash,omitempty"`
	Reason      string                     `json:"reason"`
	Warnings    []string                   `json:"warnings,omitempty"`
	Reasons     []EvaluationReasonResponse `json:"reasons"`
	CachedAt    *time.Time                 `json:"cached_at,omitempty"`
	EvaluatedAt time.Time                  `json:"evaluated_at"`
}

type AuditEventResponse struct {
	ID            string                   `json:"id"`
	CorrelationID string                   `json:"correlation_id,omitempty"`
	EventType     string                   `json:"event_type"`
	Source        string                   `json:"source,omitempty"`
	EntityType    string                   `json:"entity_type,omitempty"`
	EntityID      string                   `json:"entity_id,omitempty"`
	UpstreamID    string                   `json:"upstream_id,omitempty"`
	PolicyID      string                   `json:"policy_id,omitempty"`
	Outcome       string                   `json:"outcome,omitempty"`
	Artifact      ArtifactIdentityResponse `json:"artifact"`
	Message       string                   `json:"message,omitempty"`
	Payload       map[string]any           `json:"payload,omitempty"`
	CreatedAt     time.Time                `json:"created_at"`
}

type cacheClearResponse struct {
	Status string `json:"status"`
	Cache  string `json:"cache"`
}

type policyImportResponse struct {
	Imported int `json:"imported"`
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
	supportedPolicyTypes := corepolicy.SupportedPolicyTypesForUpstream(*u)
	policyTypes := make([]string, len(supportedPolicyTypes))
	for i := range supportedPolicyTypes {
		policyTypes[i] = string(supportedPolicyTypes[i])
	}
	effectiveCapabilities := u.EffectiveCapabilities()

	auth := UpstreamAuthResponse{
		Type:       string(domain.UpstreamAuthNone),
		Configured: false,
	}
	if u.Auth != nil {
		auth.Type = string(u.Auth.Type)
		auth.Configured = u.Auth.Configured()
		auth.Username = u.Auth.Username
		if !u.Auth.UpdatedAt.IsZero() {
			updatedAt := u.Auth.UpdatedAt
			auth.UpdatedAt = &updatedAt
		}
	}

	return &UpstreamResponse{
		ID:                   u.ID,
		Name:                 u.Name,
		Ecosystem:            string(u.Ecosystem),
		BaseURL:              u.BaseURL,
		Capabilities:         domain.UpstreamCapabilityStrings(effectiveCapabilities),
		SupportedPolicyTypes: policyTypes,
		Auth:                 auth,
		CreatedAt:            u.CreatedAt,
		UpdatedAt:            u.UpdatedAt,
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
		ID:            p.ID,
		UpstreamID:    p.UpstreamID,
		Name:          p.Name,
		Type:          string(p.Type),
		Action:        string(p.Action),
		SchemaVersion: p.SchemaVersion,
		Config:        p.Config,
		Priority:      p.Priority,
		Enabled:       p.Enabled,
		Version:       p.Version,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
	}
}

func toPoliciesResponse(policies []domain.Policy) []*PolicyResponse {
	result := make([]*PolicyResponse, len(policies))
	for i := range policies {
		result[i] = toPolicyResponse(&policies[i])
	}
	return result
}

func toPolicyVersionResponse(version *domain.PolicyVersion) *PolicyVersionResponse {
	return &PolicyVersionResponse{
		Version:       version.Version,
		UpstreamID:    version.UpstreamID,
		Name:          version.Name,
		Type:          string(version.Type),
		Action:        string(version.Action),
		SchemaVersion: version.SchemaVersion,
		Config:        version.Config,
		Priority:      version.Priority,
		Enabled:       version.Enabled,
		CreatedAt:     version.CreatedAt,
	}
}

func toPolicyVersionsResponse(versions []domain.PolicyVersion) []*PolicyVersionResponse {
	result := make([]*PolicyVersionResponse, len(versions))
	for i := range versions {
		result[i] = toPolicyVersionResponse(&versions[i])
	}
	return result
}

func toPolicyTypeResponse(d domain.PolicyTypeDescriptor) *PolicyTypeResponse {
	actions := make([]string, len(d.SupportedActions))
	for i := range d.SupportedActions {
		actions[i] = string(d.SupportedActions[i])
	}
	ecosystems := make([]string, len(d.SupportedEcosystems))
	for i := range d.SupportedEcosystems {
		ecosystems[i] = string(d.SupportedEcosystems[i])
	}

	return &PolicyTypeResponse{
		Type:                    string(d.Type),
		Summary:                 d.Summary,
		Description:             d.Description,
		Help:                    d.Help,
		CurrentSchemaVersion:    d.CurrentSchemaVersion,
		SupportedSchemaVersions: append([]int(nil), d.SupportedSchemaVersions...),
		SupportedActions:        actions,
		SupportedEcosystems:     ecosystems,
		RequiredCapabilities:    domain.UpstreamCapabilityStrings(d.RequiredCapabilities),
		Example:                 d.Example,
	}
}

func toPolicyTypesResponse(descriptors []domain.PolicyTypeDescriptor) []*PolicyTypeResponse {
	result := make([]*PolicyTypeResponse, len(descriptors))
	for i := range descriptors {
		result[i] = toPolicyTypeResponse(descriptors[i])
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
		Artifact:    artifact,
		Outcome:     string(d.Outcome),
		PolicyID:    d.PolicyID,
		PolicyHash:  d.PolicyHash,
		Reason:      d.Reason,
		Warnings:    d.Warnings,
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

func toAuditEventResponse(event *domain.AuditEvent) *AuditEventResponse {
	return &AuditEventResponse{
		ID:            event.ID,
		CorrelationID: event.CorrelationID,
		EventType:     string(event.EventType),
		Source:        event.Source,
		EntityType:    event.EntityType,
		EntityID:      event.EntityID,
		UpstreamID:    event.UpstreamID,
		PolicyID:      event.PolicyID,
		Outcome:       string(event.Outcome),
		Artifact: ArtifactIdentityResponse{
			Ecosystem: string(event.Artifact.Ecosystem),
			Namespace: event.Artifact.Namespace,
			Name:      event.Artifact.Name,
			Version:   event.Artifact.Version,
			Digest:    event.Artifact.Digest,
		},
		Message:   event.Message,
		Payload:   event.Payload,
		CreatedAt: event.CreatedAt,
	}
}

func toAuditEventsResponse(events []domain.AuditEvent) []*AuditEventResponse {
	result := make([]*AuditEventResponse, len(events))
	for i := range events {
		result[i] = toAuditEventResponse(&events[i])
	}
	return result
}

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
