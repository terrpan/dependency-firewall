package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// AuditEventRepository persists and queries audit events in PostgreSQL.
type AuditEventRepository struct {
	pool *pgxpool.Pool
}

// NewAuditEventRepository creates a new audit event repository.
func NewAuditEventRepository(pool *pgxpool.Pool) *AuditEventRepository {
	return &AuditEventRepository{pool: pool}
}

// Record inserts one audit event row.
func (r *AuditEventRepository) Record(ctx context.Context, event *domain.AuditEvent) error {
	payload, err := json.Marshal(buildAuditPayload(event))
	if err != nil {
		return fmt.Errorf("encoding audit payload: %w", err)
	}

	var entityID *string
	if looksLikeUUID(event.EntityID) {
		entityID = &event.EntityID
	}

	if _, err := r.pool.Exec(
		ctx,
		`INSERT INTO audit_events (tenant_id, event_type, entity_type, entity_id, payload, created_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
		event.TenantID,
		string(event.EventType),
		nullableAuditString(event.EntityType),
		entityID,
		payload,
		event.CreatedAt,
	); err != nil {
		return fmt.Errorf("inserting audit event: %w", err)
	}

	return nil
}

const listAuditEventsQuery = `SELECT id, tenant_id, event_type, entity_type, entity_id, payload, created_at
		 FROM audit_events
		 WHERE tenant_id = $1
		   AND ($2 = '' OR event_type = $2)
		   AND ($3 = '' OR COALESCE(payload->>'outcome', '') = $3)
		   AND ($4 = '' OR COALESCE(payload->>'correlation_id', '') = $4)
		   AND ($5 = '' OR COALESCE(payload->>'policy_id', '') = $5)
		   AND ($6 = '' OR COALESCE(payload->>'source', '') = $6)
		   AND ($7::timestamptz IS NULL OR created_at >= $7)
		   AND ($8::timestamptz IS NULL OR created_at <= $8)
		   AND (
		     $9 = ''
		     OR event_type ILIKE '%' || $9 || '%'
		     OR COALESCE(entity_type, '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->>'message', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->>'correlation_id', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->>'policy_id', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->>'upstream_id', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->'artifact'->>'namespace', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->'artifact'->>'name', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->'artifact'->>'version', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->'artifact'->>'digest', '') ILIKE '%' || $9 || '%'
		     OR COALESCE(payload->'details', '{}'::jsonb)::text ILIKE '%' || $9 || '%'
		   )
		 ORDER BY created_at DESC
		 LIMIT $10 OFFSET $11`

// ListByTenant returns tenant-scoped audit events ordered by newest first.
func (r *AuditEventRepository) ListByTenant(
	ctx context.Context,
	filter domain.AuditEventFilter,
) ([]domain.AuditEvent, error) {
	limit, offset := auditEventPage(filter)
	rows, err := r.pool.Query(
		ctx,
		listAuditEventsQuery,
		filter.TenantID,
		string(filter.EventType),
		string(filter.Outcome),
		strings.TrimSpace(filter.CorrelationID),
		strings.TrimSpace(filter.PolicyID),
		strings.TrimSpace(filter.Source),
		filter.Since,
		filter.Until,
		strings.TrimSpace(filter.Search),
		limit,
		offset,
	)
	if err != nil {
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	defer rows.Close()

	var events []domain.AuditEvent
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit event rows: %w", err)
	}

	return events, nil
}

func auditEventPage(filter domain.AuditEventFilter) (int, int) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func scanAuditEvent(row pgx.Row) (domain.AuditEvent, error) {
	var event domain.AuditEvent
	var entityType *string
	var entityID *string
	var payloadBytes []byte
	if err := row.Scan(
		&event.ID,
		&event.TenantID,
		&event.EventType,
		&entityType,
		&entityID,
		&payloadBytes,
		&event.CreatedAt,
	); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("scanning audit event row: %w", err)
	}
	if entityType != nil {
		event.EntityType = *entityType
	}
	if entityID != nil {
		event.EntityID = *entityID
	}
	if err := decodeAuditPayload(payloadBytes, &event); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("decoding audit payload: %w", err)
	}
	return event, nil
}

func buildAuditPayload(event *domain.AuditEvent) map[string]any {
	payload := map[string]any{
		"correlation_id": event.CorrelationID,
		"source":         event.Source,
		"message":        event.Message,
		"outcome":        string(event.Outcome),
		"upstream_id":    event.UpstreamID,
		"policy_id":      event.PolicyID,
		"artifact": map[string]any{
			"ecosystem": event.Artifact.Ecosystem,
			"namespace": event.Artifact.Namespace,
			"name":      event.Artifact.Name,
			"version":   event.Artifact.Version,
			"digest":    event.Artifact.Digest,
		},
		"details": event.Payload,
	}
	return payload
}

func decodeAuditPayload(data []byte, event *domain.AuditEvent) error {
	var payload struct {
		CorrelationID string                  `json:"correlation_id"`
		Source        string                  `json:"source"`
		Message       string                  `json:"message"`
		Outcome       string                  `json:"outcome"`
		UpstreamID    string                  `json:"upstream_id"`
		PolicyID      string                  `json:"policy_id"`
		Artifact      domain.ArtifactIdentity `json:"artifact"`
		Details       map[string]any          `json:"details"`
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	event.CorrelationID = payload.CorrelationID
	event.Source = payload.Source
	event.Message = payload.Message
	event.Outcome = domain.DecisionOutcome(payload.Outcome)
	event.UpstreamID = payload.UpstreamID
	event.PolicyID = payload.PolicyID
	event.Artifact = payload.Artifact
	event.Payload = payload.Details
	return nil
}

func nullableAuditString(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func looksLikeUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	return value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-'
}
