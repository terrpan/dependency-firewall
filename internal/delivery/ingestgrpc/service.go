package ingestgrpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const serviceName = "dependencyfirewall.proxyingest.v1.ProxyIngestService"
const timeLayout = time.RFC3339Nano

type proxyIngestService interface {
	RecordDecision(context.Context, *domain.Decision) error
	GetDecisionByArtifact(context.Context, string, domain.ArtifactIdentity) (*domain.Decision, error)
	ListDecisionsByTenant(context.Context, string, int, int, string) ([]domain.Decision, error)
	HasRecentAllow(context.Context, string, domain.EcosystemType, string, string) (bool, error)
	RecordAuditEvent(context.Context, *domain.AuditEvent) error
}

type proxyIngestGRPCService interface {
	RecordDecision(context.Context, *RecordDecisionRequest) (*RecordDecisionResponse, error)
	GetDecisionByArtifact(context.Context, *GetDecisionByArtifactRequest) (*GetDecisionByArtifactResponse, error)
	ListDecisionsByTenant(context.Context, *ListDecisionsByTenantRequest) (*ListDecisionsByTenantResponse, error)
	HasRecentAllow(context.Context, *HasRecentAllowRequest) (*HasRecentAllowResponse, error)
	RecordAuditEvent(context.Context, *RecordAuditEventRequest) (*RecordAuditEventResponse, error)
}

// Server serves proxy ingestion RPCs over gRPC.
type Server struct {
	service proxyIngestService
}

// NewServer creates a new Server.
func NewServer(service proxyIngestService) *Server {
	return &Server{service: service}
}

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

// Register registers the ingestion service on the given gRPC registrar.
func (s *Server) Register(registrar grpc.ServiceRegistrar) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*proxyIngestGRPCService)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "RecordDecision", Handler: s.recordDecisionHandler},
			{MethodName: "GetDecisionByArtifact", Handler: s.getDecisionByArtifactHandler},
			{MethodName: "ListDecisionsByTenant", Handler: s.listDecisionsByTenantHandler},
			{MethodName: "HasRecentAllow", Handler: s.hasRecentAllowHandler},
			{MethodName: "RecordAuditEvent", Handler: s.recordAuditEventHandler},
		},
	}, s)
}

// RecordDecision persists a proxy-evaluated decision.
func (s *Server) RecordDecision(ctx context.Context, req *RecordDecisionRequest) (*RecordDecisionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "decision is required")
	}
	decision, err := req.Decision.toDomain()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid decision: %v", err)
	}
	if strings.TrimSpace(decision.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "decision tenant_id is required")
	}
	if err := s.service.RecordDecision(ctx, decision); err != nil {
		return nil, toStatusError(err)
	}
	return &RecordDecisionResponse{Decision: fromDomainDecision(decision)}, nil
}

// GetDecisionByArtifact returns the most recent persisted decision for an artifact.
func (s *Server) GetDecisionByArtifact(ctx context.Context, req *GetDecisionByArtifactRequest) (*GetDecisionByArtifactResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	decision, err := s.service.GetDecisionByArtifact(ctx, req.TenantID, req.Artifact.toDomain())
	if err != nil {
		return nil, toStatusError(err)
	}
	return &GetDecisionByArtifactResponse{Decision: fromDomainDecision(decision)}, nil
}

// ListDecisionsByTenant lists persisted decisions for a tenant.
func (s *Server) ListDecisionsByTenant(ctx context.Context, req *ListDecisionsByTenantRequest) (*ListDecisionsByTenantResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	decisions, err := s.service.ListDecisionsByTenant(ctx, req.TenantID, req.Limit, req.Offset, req.Search)
	if err != nil {
		return nil, toStatusError(err)
	}
	response := &ListDecisionsByTenantResponse{Decisions: make([]Decision, 0, len(decisions))}
	for i := range decisions {
		response.Decisions = append(response.Decisions, fromDomainDecision(&decisions[i]))
	}
	return response, nil
}

// HasRecentAllow reports whether an artifact has a recent allow decision.
func (s *Server) HasRecentAllow(ctx context.Context, req *HasRecentAllowRequest) (*HasRecentAllowResponse, error) {
	if req == nil || strings.TrimSpace(req.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	allowed, err := s.service.HasRecentAllow(ctx, req.TenantID, req.Ecosystem, req.Namespace, req.Name)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &HasRecentAllowResponse{Allowed: allowed}, nil
}

// RecordAuditEvent persists a proxy-emitted audit event.
func (s *Server) RecordAuditEvent(ctx context.Context, req *RecordAuditEventRequest) (*RecordAuditEventResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "event is required")
	}
	event, err := req.Event.toDomain()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid event: %v", err)
	}
	if strings.TrimSpace(event.TenantID) == "" {
		return nil, status.Error(codes.InvalidArgument, "event tenant_id is required")
	}
	if err := s.service.RecordAuditEvent(ctx, event); err != nil {
		return nil, toStatusError(err)
	}
	return &RecordAuditEventResponse{Event: fromDomainAuditEvent(event)}, nil
}

func (s *Server) recordDecisionHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &RecordDecisionRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).RecordDecision(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/RecordDecision"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).RecordDecision(ctx, req.(*RecordDecisionRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) getDecisionByArtifactHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &GetDecisionByArtifactRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).GetDecisionByArtifact(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/GetDecisionByArtifact"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).GetDecisionByArtifact(ctx, req.(*GetDecisionByArtifactRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) listDecisionsByTenantHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ListDecisionsByTenantRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).ListDecisionsByTenant(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ListDecisionsByTenant"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).ListDecisionsByTenant(ctx, req.(*ListDecisionsByTenantRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) hasRecentAllowHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &HasRecentAllowRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).HasRecentAllow(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/HasRecentAllow"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).HasRecentAllow(ctx, req.(*HasRecentAllowRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) recordAuditEventHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &RecordAuditEventRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).RecordAuditEvent(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/RecordAuditEvent"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).RecordAuditEvent(ctx, req.(*RecordAuditEventRequest))
	}
	return interceptor(ctx, req, info, handler)
}

// RecordDecision invokes the remote ingestion service and returns the persisted decision.
func RecordDecision(ctx context.Context, conn grpc.ClientConnInterface, decision *domain.Decision) (*domain.Decision, error) {
	if decision == nil {
		return nil, fmt.Errorf("decision is required")
	}
	response := &RecordDecisionResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/RecordDecision", &RecordDecisionRequest{Decision: fromDomainDecision(decision)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	return response.Decision.toDomain()
}

// GetDecisionByArtifact invokes the remote ingestion service for one artifact decision.
func GetDecisionByArtifact(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	response := &GetDecisionByArtifactResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/GetDecisionByArtifact", &GetDecisionByArtifactRequest{TenantID: tenantID, Artifact: fromDomainArtifactIdentity(artifact)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	return response.Decision.toDomain()
}

// ListDecisionsByTenant invokes the remote ingestion service for tenant decisions.
func ListDecisionsByTenant(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, limit, offset int, search string) ([]domain.Decision, error) {
	response := &ListDecisionsByTenantResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/ListDecisionsByTenant", &ListDecisionsByTenantRequest{TenantID: tenantID, Limit: limit, Offset: offset, Search: search}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	decisions := make([]domain.Decision, 0, len(response.Decisions))
	for i := range response.Decisions {
		decision, err := response.Decisions[i].toDomain()
		if err != nil {
			return nil, fmt.Errorf("decoding decision: %w", err)
		}
		decisions = append(decisions, *decision)
	}
	return decisions, nil
}

// HasRecentAllow invokes the remote ingestion service for recent-allow lookup.
func HasRecentAllow(ctx context.Context, conn grpc.ClientConnInterface, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	response := &HasRecentAllowResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/HasRecentAllow", &HasRecentAllowRequest{TenantID: tenantID, Ecosystem: ecosystem, Namespace: namespace, Name: name}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return false, mapClientError(err)
	}
	return response.Allowed, nil
}

// RecordAuditEvent invokes the remote ingestion service and returns the persisted audit event.
func RecordAuditEvent(ctx context.Context, conn grpc.ClientConnInterface, event *domain.AuditEvent) (*domain.AuditEvent, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}
	response := &RecordAuditEventResponse{}
	if err := conn.Invoke(ctx, "/"+serviceName+"/RecordAuditEvent", &RecordAuditEventRequest{Event: fromDomainAuditEvent(event)}, response, grpc.ForceCodec(jsonCodec{})); err != nil {
		return nil, mapClientError(err)
	}
	return response.Event.toDomain()
}

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

func toStatusError(err error) error {
	switch {
	case errors.Is(err, domain.ErrArtifactNotFound):
		return status.Error(codes.NotFound, domain.ErrArtifactNotFound.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func mapClientError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	if st.Code() == codes.NotFound && st.Message() == domain.ErrArtifactNotFound.Error() {
		return domain.ErrArtifactNotFound
	}
	return err
}
