package ingestgrpc

import "github.com/danielterry/dependency-firewall/internal/core/domain"

type RecordDecisionRequest struct {
	Decision Decision `json:"decision"`
}

type RecordDecisionResponse struct {
	Decision Decision `json:"decision"`
}

type GetDecisionByArtifactRequest struct {
	TenantID string           `json:"tenant_id"`
	Artifact ArtifactIdentity `json:"artifact"`
}

type GetDecisionByArtifactResponse struct {
	Decision Decision `json:"decision"`
}

type ListDecisionsByTenantRequest struct {
	TenantID string `json:"tenant_id"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
	Search   string `json:"search"`
}

type ListDecisionsByTenantResponse struct {
	Decisions []Decision `json:"decisions"`
}

type HasRecentAllowRequest struct {
	TenantID  string               `json:"tenant_id"`
	Ecosystem domain.EcosystemType `json:"ecosystem"`
	Namespace string               `json:"namespace"`
	Name      string               `json:"name"`
}

type HasRecentAllowResponse struct {
	Allowed bool `json:"allowed"`
}

type RecordAuditEventRequest struct {
	Event AuditEvent `json:"event"`
}

type RecordAuditEventResponse struct {
	Event AuditEvent `json:"event"`
}

type Decision struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	Artifact    ArtifactIdentity       `json:"artifact"`
	Outcome     domain.DecisionOutcome `json:"outcome"`
	PolicyID    string                 `json:"policy_id"`
	PolicyHash  string                 `json:"policy_hash"`
	Reason      string                 `json:"reason"`
	Reasons     []EvaluationReason     `json:"reasons"`
	Warnings    []string               `json:"warnings"`
	CachedAt    *string                `json:"cached_at,omitempty"`
	EvaluatedAt string                 `json:"evaluated_at,omitempty"`
}

type EvaluationReason struct {
	PolicyID   string                `json:"policy_id"`
	PolicyName string                `json:"policy_name"`
	Category   domain.ReasonCategory `json:"category"`
	Action     domain.PolicyAction   `json:"action"`
	Message    string                `json:"message"`
}

type ArtifactIdentity struct {
	Ecosystem domain.EcosystemType `json:"ecosystem"`
	Namespace string               `json:"namespace"`
	Name      string               `json:"name"`
	Version   string               `json:"version"`
	Digest    string               `json:"digest"`
}

type AuditEvent struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	CorrelationID string                 `json:"correlation_id"`
	EventType     domain.AuditEventType  `json:"event_type"`
	Source        string                 `json:"source"`
	EntityType    string                 `json:"entity_type"`
	EntityID      string                 `json:"entity_id"`
	UpstreamID    string                 `json:"upstream_id"`
	PolicyID      string                 `json:"policy_id"`
	Outcome       domain.DecisionOutcome `json:"outcome"`
	Artifact      ArtifactIdentity       `json:"artifact"`
	Message       string                 `json:"message"`
	Payload       map[string]any         `json:"payload"`
	CreatedAt     string                 `json:"created_at,omitempty"`
}
