package ingestgrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const (
	ServiceName                 = "dependencyfirewall.proxyingest.v1.ProxyIngestService"
	RecordDecisionMethod        = "/" + ServiceName + "/RecordDecision"
	GetDecisionByArtifactMethod = "/" + ServiceName + "/GetDecisionByArtifact"
	ListDecisionsByTenantMethod = "/" + ServiceName + "/ListDecisionsByTenant"
	HasRecentAllowMethod        = "/" + ServiceName + "/HasRecentAllow"
	RecordAuditEventMethod      = "/" + ServiceName + "/RecordAuditEvent"
	timeLayout                  = time.RFC3339Nano
)

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

// TenantIDFromRequest returns the tenant id carried by ingest gRPC requests.
func TenantIDFromRequest(req any) string {
	switch typed := req.(type) {
	case *RecordDecisionRequest:
		return typed.Decision.TenantID
	case *GetDecisionByArtifactRequest:
		return typed.TenantID
	case *ListDecisionsByTenantRequest:
		return typed.TenantID
	case *HasRecentAllowRequest:
		return typed.TenantID
	case *RecordAuditEventRequest:
		return typed.Event.TenantID
	default:
		return ""
	}
}

func FromDomainDecision(decision *domain.Decision) Decision {
	result := Decision{
		ID:          decision.ID,
		TenantID:    decision.TenantID,
		Artifact:    FromDomainArtifactIdentity(decision.Artifact),
		Outcome:     decision.Outcome,
		PolicyID:    decision.PolicyID,
		PolicyHash:  decision.PolicyHash,
		Reason:      decision.Reason,
		Reasons:     make([]EvaluationReason, 0, len(decision.Reasons)),
		Warnings:    append([]string(nil), decision.Warnings...),
		EvaluatedAt: formatTime(decision.EvaluatedAt),
	}
	for i := range decision.Reasons {
		result.Reasons = append(result.Reasons, FromDomainEvaluationReason(decision.Reasons[i]))
	}
	if decision.CachedAt != nil {
		cachedAt := formatTime(*decision.CachedAt)
		result.CachedAt = &cachedAt
	}
	return result
}

func (d Decision) ToDomain() (*domain.Decision, error) {
	evaluatedAt, err := parseTime(d.EvaluatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing evaluated_at: %w", err)
	}
	result := &domain.Decision{
		ID:          d.ID,
		TenantID:    d.TenantID,
		Artifact:    d.Artifact.ToDomain(),
		Outcome:     d.Outcome,
		PolicyID:    d.PolicyID,
		PolicyHash:  d.PolicyHash,
		Reason:      d.Reason,
		Reasons:     make([]domain.EvaluationReason, 0, len(d.Reasons)),
		Warnings:    append([]string(nil), d.Warnings...),
		EvaluatedAt: evaluatedAt,
	}
	for i := range d.Reasons {
		result.Reasons = append(result.Reasons, d.Reasons[i].ToDomain())
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

func FromDomainEvaluationReason(reason domain.EvaluationReason) EvaluationReason {
	return EvaluationReason{
		PolicyID:   reason.PolicyID,
		PolicyName: reason.PolicyName,
		Category:   reason.Category,
		Action:     reason.Action,
		Message:    reason.Message,
	}
}

func (r EvaluationReason) ToDomain() domain.EvaluationReason {
	return domain.EvaluationReason{
		PolicyID:   r.PolicyID,
		PolicyName: r.PolicyName,
		Category:   r.Category,
		Action:     r.Action,
		Message:    r.Message,
	}
}

func FromDomainArtifactIdentity(artifact domain.ArtifactIdentity) ArtifactIdentity {
	return ArtifactIdentity{
		Ecosystem: artifact.Ecosystem,
		Namespace: artifact.Namespace,
		Name:      artifact.Name,
		Version:   artifact.Version,
		Digest:    artifact.Digest,
	}
}

func (a ArtifactIdentity) ToDomain() domain.ArtifactIdentity {
	return domain.ArtifactIdentity{
		Ecosystem: a.Ecosystem,
		Namespace: a.Namespace,
		Name:      a.Name,
		Version:   a.Version,
		Digest:    a.Digest,
	}
}

func FromDomainAuditEvent(event *domain.AuditEvent) AuditEvent {
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
		Artifact:      FromDomainArtifactIdentity(event.Artifact),
		Message:       event.Message,
		Payload:       cloneMap(event.Payload),
		CreatedAt:     formatTime(event.CreatedAt),
	}
}

func (e AuditEvent) ToDomain() (*domain.AuditEvent, error) {
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
		Artifact:      e.Artifact.ToDomain(),
		Message:       e.Message,
		Payload:       cloneMap(e.Payload),
		CreatedAt:     createdAt,
	}, nil
}

func RecordDecision(ctx context.Context, conn grpc.ClientConnInterface, decision *domain.Decision) (*domain.Decision, error) {
	if decision == nil {
		return nil, fmt.Errorf("decision is required")
	}
	response := &RecordDecisionResponse{}
	if err := conn.Invoke(ctx, RecordDecisionMethod, &RecordDecisionRequest{Decision: FromDomainDecision(decision)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, MapClientError(err)
	}
	return response.Decision.ToDomain()
}

func GetDecisionByArtifact(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	response := &GetDecisionByArtifactResponse{}
	if err := conn.Invoke(ctx, GetDecisionByArtifactMethod, &GetDecisionByArtifactRequest{TenantID: tenantID, Artifact: FromDomainArtifactIdentity(artifact)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, MapClientError(err)
	}
	return response.Decision.ToDomain()
}

func ListDecisionsByTenant(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, limit, offset int, search string) ([]domain.Decision, error) {
	response := &ListDecisionsByTenantResponse{}
	if err := conn.Invoke(ctx, ListDecisionsByTenantMethod, &ListDecisionsByTenantRequest{TenantID: tenantID, Limit: limit, Offset: offset, Search: search}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, MapClientError(err)
	}
	decisions := make([]domain.Decision, 0, len(response.Decisions))
	for i := range response.Decisions {
		decision, err := response.Decisions[i].ToDomain()
		if err != nil {
			return nil, fmt.Errorf("decoding decision: %w", err)
		}
		decisions = append(decisions, *decision)
	}
	return decisions, nil
}

func HasRecentAllow(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	response := &HasRecentAllowResponse{}
	if err := conn.Invoke(ctx, HasRecentAllowMethod, &HasRecentAllowRequest{TenantID: tenantID, Ecosystem: ecosystem, Namespace: namespace, Name: name}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return false, MapClientError(err)
	}
	return response.Allowed, nil
}

func RecordAuditEvent(ctx context.Context, conn grpc.ClientConnInterface, event *domain.AuditEvent) (*domain.AuditEvent, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}
	response := &RecordAuditEventResponse{}
	if err := conn.Invoke(ctx, RecordAuditEventMethod, &RecordAuditEventRequest{Event: FromDomainAuditEvent(event)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, MapClientError(err)
	}
	return response.Event.ToDomain()
}

func MapClientError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	if st.Code() == codes.NotFound && st.Message() == domain.ErrArtifactNotFound.Error() {
		return domain.ErrArtifactNotFound
	}
	return err
}

func ToStatusError(err error) error {
	switch {
	case errors.Is(err, domain.ErrArtifactNotFound):
		return status.Error(codes.NotFound, domain.ErrArtifactNotFound.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
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

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}
