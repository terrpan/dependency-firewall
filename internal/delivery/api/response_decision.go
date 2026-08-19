package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DecisionResponse is the wire form of a persisted policy decision. PolicyID and Reason identify the policy that
// supplied the user-facing outcome, Reasons retains every contributing match, Warnings holds non-enforcing findings
// from dry-run or unknown-dependency-context policies, and CachedAt is set when the decision was served from cache.
type DecisionResponse struct {
	ID          string                     `json:"id"`
	Artifact    ArtifactIdentityResponse   `json:"artifact"`
	Outcome     string                     `json:"outcome"`
	PolicyID    string                     `json:"policy_id"`
	PolicyHash  string                     `json:"policy_hash,omitempty"`
	Reason      string                     `json:"reason"`
	Warnings    []string                   `json:"warnings,omitempty"`
	Reasons     []EvaluationReasonResponse `json:"reasons"`
	CachedAt    *time.Time                 `json:"cached_at,omitempty"`
	EvaluatedAt time.Time                  `json:"evaluated_at"`
}

func toDecisionResponse(d *domain.Decision) *DecisionResponse {
	artifact := ArtifactIdentityResponse{
		Ecosystem: string(d.Artifact.Ecosystem),
		Namespace: d.Artifact.Namespace,
		Name:      d.Artifact.Name,
		Version:   d.Artifact.Version,
		Digest:    d.Artifact.Digest,
	}

	reasons := make([]EvaluationReasonResponse, len(d.Reasons))
	for i, r := range d.Reasons {
		reasons[i] = EvaluationReasonResponse{
			PolicyID:   r.PolicyID,
			PolicyName: r.PolicyName,
			Category:   string(r.Category),
			Action:     string(r.Action),
			Message:    r.Message,
		}
	}

	return &DecisionResponse{
		ID:          d.ID,
		Artifact:    artifact,
		Outcome:     string(d.Outcome),
		PolicyID:    d.PolicyID,
		PolicyHash:  d.PolicyHash,
		Reason:      d.Reason,
		Warnings:    d.Warnings,
		Reasons:     reasons,
		CachedAt:    d.CachedAt,
		EvaluatedAt: d.EvaluatedAt,
	}
}

func toDecisionsResponse(decisions []domain.Decision) []*DecisionResponse {
	result := make([]*DecisionResponse, len(decisions))
	for i := range decisions {
		result[i] = toDecisionResponse(&decisions[i])
	}
	return result
}
