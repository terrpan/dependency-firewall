package ingestgrpc

import (
	"fmt"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const timeLayout = time.RFC3339Nano

func fromDomainDecision(decision *domain.Decision) Decision {
	result := Decision{
		ID:          decision.ID,
		TenantID:    decision.TenantID,
		Artifact:    fromDomainArtifactIdentity(decision.Artifact),
		Outcome:     decision.Outcome,
		PolicyID:    decision.PolicyID,
		PolicyHash:  decision.PolicyHash,
		Reason:      decision.Reason,
		Reasons:     make([]EvaluationReason, 0, len(decision.Reasons)),
		Warnings:    append([]string(nil), decision.Warnings...),
		EvaluatedAt: formatTime(decision.EvaluatedAt),
	}
	for i := range decision.Reasons {
		result.Reasons = append(result.Reasons, fromDomainEvaluationReason(decision.Reasons[i]))
	}
	if decision.CachedAt != nil {
		cachedAt := formatTime(*decision.CachedAt)
		result.CachedAt = &cachedAt
	}
	return result
}

func (d Decision) toDomain() (*domain.Decision, error) {
	evaluatedAt, err := parseTime(d.EvaluatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing evaluated_at: %w", err)
	}
	result := &domain.Decision{
		ID:          d.ID,
		TenantID:    d.TenantID,
		Artifact:    d.Artifact.toDomain(),
		Outcome:     d.Outcome,
		PolicyID:    d.PolicyID,
		PolicyHash:  d.PolicyHash,
		Reason:      d.Reason,
		Reasons:     make([]domain.EvaluationReason, 0, len(d.Reasons)),
		Warnings:    append([]string(nil), d.Warnings...),
		EvaluatedAt: evaluatedAt,
	}
	for i := range d.Reasons {
		result.Reasons = append(result.Reasons, d.Reasons[i].toDomain())
	}
	if d.CachedAt != nil {
		cachedAt, err := parseTime(*d.CachedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing cached_at: %w", err)
		}
		result.CachedAt = &cachedAt
	}
	return result, nil
}

func fromDomainEvaluationReason(reason domain.EvaluationReason) EvaluationReason {
	return EvaluationReason{
		PolicyID:   reason.PolicyID,
		PolicyName: reason.PolicyName,
		Category:   reason.Category,
		Action:     reason.Action,
		Message:    reason.Message,
	}
}

func (r EvaluationReason) toDomain() domain.EvaluationReason {
	return domain.EvaluationReason{
		PolicyID:   r.PolicyID,
		PolicyName: r.PolicyName,
		Category:   r.Category,
		Action:     r.Action,
		Message:    r.Message,
	}
}

func fromDomainArtifactIdentity(artifact domain.ArtifactIdentity) ArtifactIdentity {
	return ArtifactIdentity{
		Ecosystem: artifact.Ecosystem,
		Namespace: artifact.Namespace,
		Name:      artifact.Name,
		Version:   artifact.Version,
		Digest:    artifact.Digest,
	}
}

func (a ArtifactIdentity) toDomain() domain.ArtifactIdentity {
	return domain.ArtifactIdentity{
		Ecosystem: a.Ecosystem,
		Namespace: a.Namespace,
		Name:      a.Name,
		Version:   a.Version,
		Digest:    a.Digest,
	}
}

func fromDomainAuditEvent(event *domain.AuditEvent) AuditEvent {
	return AuditEvent{
		ID:            event.ID,
		TenantID:      event.TenantID,
		CorrelationID: event.CorrelationID,
		EventType:     event.EventType,
		Source:        event.Source,
		EntityType:    event.EntityType,
		EntityID:      event.EntityID,
		UpstreamID:    event.UpstreamID,
		PolicyID:      event.PolicyID,
		Outcome:       event.Outcome,
		Artifact:      fromDomainArtifactIdentity(event.Artifact),
		Message:       event.Message,
		Payload:       cloneMap(event.Payload),
		CreatedAt:     formatTime(event.CreatedAt),
	}
}

func (e AuditEvent) toDomain() (*domain.AuditEvent, error) {
	createdAt, err := parseTime(e.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	return &domain.AuditEvent{
		ID:            e.ID,
		TenantID:      e.TenantID,
		CorrelationID: e.CorrelationID,
		EventType:     e.EventType,
		Source:        e.Source,
		EntityType:    e.EntityType,
		EntityID:      e.EntityID,
		UpstreamID:    e.UpstreamID,
		PolicyID:      e.PolicyID,
		Outcome:       e.Outcome,
		Artifact:      e.Artifact.toDomain(),
		Message:       e.Message,
		Payload:       cloneMap(e.Payload),
		CreatedAt:     createdAt,
	}, nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timeLayout)
}

func parseTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(timeLayout, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

func cloneMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
