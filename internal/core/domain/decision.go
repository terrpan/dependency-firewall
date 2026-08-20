package domain

import "time"

// DecisionOutcome is the result of policy evaluation.
type DecisionOutcome string

// Evaluation is deny-wins: any matching deny policy produces DecisionDeny, an allow match never overrides it, and an
// artifact that matches no applicable policy defaults to DecisionAllow.
const (
	DecisionAllow DecisionOutcome = "allow"
	DecisionDeny  DecisionOutcome = "deny"
)

// ReasonCategory classifies why a decision was made.
type ReasonCategory string

// Reason categories distinguish an enforced policy match from a non-enforcing warning (dry-run or unknown dependency
// context), the default allow when nothing matched, enrichment that could not be obtained, a decision replayed from
// cache, and a fail-closed error raised while loading or evaluating policies.
const (
	ReasonPolicyMatch             ReasonCategory = "policy_match"
	ReasonPolicyWarning           ReasonCategory = "policy_warning"
	ReasonNoMatchingPolicy        ReasonCategory = "no_matching_policy"
	ReasonEnrichmentFailure       ReasonCategory = "enrichment_failure"
	ReasonCached                  ReasonCategory = "cached"
	ReasonCategoryEvaluationError ReasonCategory = "evaluation_error"
)

// Decision records the outcome of a policy evaluation.
type Decision struct {
	ID                string
	TenantID          string
	OrganizationID    string
	TeamID            string
	UpstreamID        string
	CredentialID      string
	Artifact          ArtifactIdentity
	Outcome           DecisionOutcome
	PolicyID          string
	PolicyHash        string
	DependencyContext *DependencyContext
	Reason            string // user-facing reason
	Reasons           []EvaluationReason
	Warnings          []string // user-facing warnings from warn-mode policies
	CachedAt          *time.Time
	EvaluatedAt       time.Time
}

// EvaluationReason is one reason contributing to a decision.
type EvaluationReason struct {
	PolicyID   string
	PolicyName string
	Category   ReasonCategory
	Action     PolicyAction
	Message    string
}
