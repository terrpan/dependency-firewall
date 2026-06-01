package domain

import "time"

// DecisionOutcome is the result of policy evaluation.
type DecisionOutcome string

const (
	DecisionAllow DecisionOutcome = "allow"
	DecisionDeny  DecisionOutcome = "deny"
)

// ReasonCategory classifies why a decision was made.
type ReasonCategory string

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
	ID          string
	TenantID    string
	Artifact    ArtifactIdentity
	Outcome     DecisionOutcome
	PolicyID    string
	PolicyHash  string
	Reason      string // user-facing reason
	Reasons     []EvaluationReason
	Warnings    []string // user-facing warnings from warn-mode policies
	CachedAt    *time.Time
	EvaluatedAt time.Time
}

// EvaluationReason is one reason contributing to a decision.
type EvaluationReason struct {
	PolicyID   string
	PolicyName string
	Category   ReasonCategory
	Action     PolicyAction
	Message    string
}
