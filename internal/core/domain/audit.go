package domain

import "time"

// AuditEventType classifies a structured audit event in the evaluation flow.
type AuditEventType string

const (
	AuditEventProxyRequestReceived AuditEventType = "proxy_request_received"
	AuditEventEvaluationStarted    AuditEventType = "evaluation_started"
	AuditEventArtifactNormalized   AuditEventType = "artifact_normalized"
	AuditEventReferenceResolved    AuditEventType = "reference_resolved"
	AuditEventDecisionCacheHit     AuditEventType = "decision_cache_hit"
	AuditEventDecisionCacheMiss    AuditEventType = "decision_cache_miss"
	AuditEventEnrichmentStarted    AuditEventType = "enrichment_started"
	AuditEventMetadataCacheHit     AuditEventType = "metadata_cache_hit"
	AuditEventMetadataCacheMiss    AuditEventType = "metadata_cache_miss"
	AuditEventEnrichmentFailed     AuditEventType = "enrichment_failed"
	AuditEventPoliciesLoaded       AuditEventType = "policies_loaded"
	AuditEventPolicyMatched        AuditEventType = "policy_matched"
	AuditEventDecisionComputed     AuditEventType = "decision_computed"
	AuditEventDecisionPersisted    AuditEventType = "decision_persisted"
	AuditEventUpstreamFetchStarted AuditEventType = "upstream_fetch_started"
	AuditEventUpstreamFetchFailed  AuditEventType = "upstream_fetch_failed"
	AuditEventRequestAllowed       AuditEventType = "request_allowed"
	AuditEventRequestDenied        AuditEventType = "request_denied"
	AuditEventRequestForwarded     AuditEventType = "request_forwarded"
	AuditEventError                AuditEventType = "error"
)

// AuditFailureMode controls how the system reacts when required audit storage fails.
type AuditFailureMode string

const (
	AuditFailureModeFailOpen   AuditFailureMode = "fail_open"
	AuditFailureModeFailClosed AuditFailureMode = "fail_closed"
)

// AuditDetailLevel controls how much enrichment detail is included in audit payloads.
type AuditDetailLevel string

const (
	AuditDetailLevelMinimal AuditDetailLevel = "minimal"
	AuditDetailLevelSummary AuditDetailLevel = "summary"
	AuditDetailLevelFull    AuditDetailLevel = "full"
)

// AuditEvent is an append-only structured audit record.
type AuditEvent struct {
	ID            string
	TenantID      string
	CorrelationID string
	EventType     AuditEventType
	Source        string
	EntityType    string
	EntityID      string
	UpstreamID    string
	PolicyID      string
	Outcome       DecisionOutcome
	Artifact      ArtifactIdentity
	Message       string
	Payload       map[string]any
	CreatedAt     time.Time
}

// AuditEventFilter scopes tenant-aware audit queries.
type AuditEventFilter struct {
	TenantID      string
	Limit         int
	Offset        int
	Search        string
	EventType     AuditEventType
	Outcome       DecisionOutcome
	CorrelationID string
	PolicyID      string
	Source        string
	Since         *time.Time
	Until         *time.Time
}
