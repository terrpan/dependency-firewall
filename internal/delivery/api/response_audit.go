package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// AuditEventResponse is the wire form of one append-only audit record. CorrelationID ties together every event emitted
// for a single proxy request, and Payload carries the evidence retained at the configured audit detail level. TenantID
// is deliberately absent because audit reads are already scoped to the requesting tenant.
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
