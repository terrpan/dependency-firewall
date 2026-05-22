package ingestgrpc

import wire "github.com/danielterry/dependency-firewall/internal/wire/ingestgrpc"

type RecordDecisionRequest = wire.RecordDecisionRequest
type RecordDecisionResponse = wire.RecordDecisionResponse
type GetDecisionByArtifactRequest = wire.GetDecisionByArtifactRequest
type GetDecisionByArtifactResponse = wire.GetDecisionByArtifactResponse
type ListDecisionsByTenantRequest = wire.ListDecisionsByTenantRequest
type ListDecisionsByTenantResponse = wire.ListDecisionsByTenantResponse
type HasRecentAllowRequest = wire.HasRecentAllowRequest
type HasRecentAllowResponse = wire.HasRecentAllowResponse
type RecordAuditEventRequest = wire.RecordAuditEventRequest
type RecordAuditEventResponse = wire.RecordAuditEventResponse
type Decision = wire.Decision
type EvaluationReason = wire.EvaluationReason
type ArtifactIdentity = wire.ArtifactIdentity
type AuditEvent = wire.AuditEvent
