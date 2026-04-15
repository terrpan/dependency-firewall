package policy

import (
	"fmt"
	"sort"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

// Evaluator evaluates policies against an access request.
type Evaluator struct{}

// NewEvaluator creates a new policy evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// Evaluate runs all policies against the request and returns a decision.
//
// Rules:
//  1. Only enabled policies are evaluated.
//  2. Policies are evaluated in priority order (ascending), then by name for determinism.
//  3. Deny overrides allow — if ANY deny matches, outcome is deny.
//  4. The first user-facing deny reason is used as the decision reason.
//  5. All matched reasons (allow and deny) are logged for audit.
//  6. If no policies match, default is allow.
//  7. Condition lookup or evaluation errors are treated as deny with evaluation_error category.
func (e *Evaluator) Evaluate(req domain.AccessRequest, policies []domain.Policy) domain.Decision {
	enabled := filterEnabled(policies)
	sort.SliceStable(enabled, func(i, j int) bool {
		if enabled[i].Priority != enabled[j].Priority {
			return enabled[i].Priority < enabled[j].Priority
		}
		return enabled[i].Name < enabled[j].Name
	})

	var reasons []domain.EvaluationReason
	var firstDenyReason string
	hasDeny := false

	for _, p := range enabled {
		cond, err := condition.ForType(p.Type)
		if err != nil {
			er := domain.EvaluationReason{
				PolicyID:   p.ID,
				PolicyName: p.Name,
				Category:   domain.ReasonCategoryEvaluationError,
				Action:     domain.PolicyActionDeny,
				Message:    fmt.Sprintf("unknown policy type %q: %v", p.Type, err),
			}
			reasons = append(reasons, er)
			if !hasDeny {
				hasDeny = true
				firstDenyReason = er.Message
			}
			continue
		}

		matched, reason, err := cond.Evaluate(req, p.Config)
		if err != nil {
			er := domain.EvaluationReason{
				PolicyID:   p.ID,
				PolicyName: p.Name,
				Category:   domain.ReasonCategoryEvaluationError,
				Action:     domain.PolicyActionDeny,
				Message:    fmt.Sprintf("condition evaluation error for policy %q: %v", p.Name, err),
			}
			reasons = append(reasons, er)
			if !hasDeny {
				hasDeny = true
				firstDenyReason = er.Message
			}
			continue
		}

		if !matched {
			continue
		}

		er := domain.EvaluationReason{
			PolicyID:   p.ID,
			PolicyName: p.Name,
			Category:   domain.ReasonPolicyMatch,
			Action:     p.Action,
			Message:    reason,
		}
		reasons = append(reasons, er)

		if p.Action == domain.PolicyActionDeny && !hasDeny {
			hasDeny = true
			firstDenyReason = reason
		}
	}

	outcome := domain.DecisionAllow
	userReason := "no matching policy"
	policyID := ""

	if hasDeny {
		outcome = domain.DecisionDeny
		userReason = firstDenyReason
		for _, r := range reasons {
			if r.Action == domain.PolicyActionDeny {
				policyID = r.PolicyID
				break
			}
		}
	} else if len(reasons) > 0 {
		userReason = reasons[0].Message
		policyID = reasons[0].PolicyID
	}

	if len(reasons) == 0 {
		reasons = append(reasons, domain.EvaluationReason{
			Category: domain.ReasonNoMatchingPolicy,
			Message:  "no matching policy",
		})
	}

	return domain.Decision{
		TenantID:    req.TenantID,
		Artifact:    req.Artifact,
		Outcome:     outcome,
		PolicyID:    policyID,
		Reason:      userReason,
		Reasons:     reasons,
		EvaluatedAt: time.Now(),
	}
}

func filterEnabled(policies []domain.Policy) []domain.Policy {
	result := make([]domain.Policy, 0, len(policies))
	for _, p := range policies {
		if p.Enabled {
			result = append(result, p)
		}
	}
	return result
}
