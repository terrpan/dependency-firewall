package policy

import (
	"fmt"
	"sort"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
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

	state := evaluationState{
		reasons: make([]domain.EvaluationReason, 0, len(enabled)),
	}
	for _, policy := range enabled {
		state.evaluatePolicy(req, policy)
	}
	return state.decision(req)
}

type evaluationState struct {
	reasons         []domain.EvaluationReason
	warnings        []string
	firstDenyReason string
	hasDeny         bool
}

func (s *evaluationState) evaluatePolicy(req domain.AccessRequest, policy domain.Policy) {
	targetMode := targetEvaluationMode(req, policy.Target)
	if targetMode == targetSkip {
		return
	}

	cond, err := conditionForType(policy.Type)
	if err != nil {
		s.addDeny(domain.EvaluationReason{
			PolicyID:   policy.ID,
			PolicyName: policy.Name,
			Category:   domain.ReasonCategoryEvaluationError,
			Action:     domain.PolicyActionDeny,
			Message:    fmt.Sprintf("unknown policy type %q: %v", policy.Type, err),
		})
		return
	}

	matched, reason, err := cond.Evaluate(req, policy.Config)
	if err != nil {
		s.addDeny(domain.EvaluationReason{
			PolicyID:   policy.ID,
			PolicyName: policy.Name,
			Category:   domain.ReasonCategoryEvaluationError,
			Action:     domain.PolicyActionDeny,
			Message:    fmt.Sprintf("condition evaluation error for policy %q: %v", policy.Name, err),
		})
		return
	}
	if !matched {
		return
	}

	// When dry_run is enabled, record the match as a warning instead of
	// a hard allow/deny. The decision outcome is unaffected.
	if isWarnMode(policy.Config) || targetMode == targetWarn {
		s.reasons = append(s.reasons, domain.EvaluationReason{
			PolicyID:   policy.ID,
			PolicyName: policy.Name,
			Category:   domain.ReasonPolicyWarning,
			Action:     policy.Action,
			Message:    reason,
		})
		s.warnings = append(s.warnings, fmt.Sprintf("[%s] %s", policy.Name, reason))
		return
	}

	evaluationReason := domain.EvaluationReason{
		PolicyID:   policy.ID,
		PolicyName: policy.Name,
		Category:   domain.ReasonPolicyMatch,
		Action:     policy.Action,
		Message:    reason,
	}
	s.reasons = append(s.reasons, evaluationReason)
	if policy.Action == domain.PolicyActionDeny && !s.hasDeny {
		s.hasDeny = true
		s.firstDenyReason = reason
	}
}

func (s *evaluationState) addDeny(reason domain.EvaluationReason) {
	s.reasons = append(s.reasons, reason)
	if s.hasDeny {
		return
	}
	s.hasDeny = true
	s.firstDenyReason = reason.Message
}

func (s *evaluationState) decision(req domain.AccessRequest) domain.Decision {
	outcome := domain.DecisionAllow
	userReason := "no matching policy"
	policyID := ""

	if s.hasDeny {
		outcome = domain.DecisionDeny
		userReason = s.firstDenyReason
		policyID = firstDenyPolicyID(s.reasons)
	} else if len(s.reasons) > 0 {
		userReason = s.reasons[0].Message
		policyID = s.reasons[0].PolicyID
	}

	if len(s.reasons) == 0 {
		s.reasons = append(s.reasons, domain.EvaluationReason{
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
		Reasons:     s.reasons,
		Warnings:    s.warnings,
		EvaluatedAt: time.Now(),
	}
}

func firstDenyPolicyID(reasons []domain.EvaluationReason) string {
	for _, reason := range reasons {
		if reason.Action == domain.PolicyActionDeny {
			return reason.PolicyID
		}
	}
	return ""
}

// isWarnMode returns true if the policy config enables dry-run evaluation.
func isWarnMode(config domain.PolicyConfig) bool {
	if config == nil {
		return false
	}
	return config.DryRunEnabled()
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

type targetMode int

const (
	targetApply targetMode = iota
	targetWarn
	targetSkip
)

func targetEvaluationMode(req domain.AccessRequest, target *domain.PolicyTarget) targetMode {
	if target == nil {
		return targetApply
	}

	ctx := domain.NewUnknownDependencyContext()
	if req.DependencyContext != nil {
		ctx = req.DependencyContext.Normalize()
	}
	if ctx.Scope == domain.DependencyScopeUnknown {
		switch target.OnUnknown {
		case domain.DependencyUnknownDeny:
			return targetApply
		case domain.DependencyUnknownSkip:
			return targetSkip
		default:
			return targetWarn
		}
	}

	if len(target.DependencyScopes) > 0 && !scopeMatches(target.DependencyScopes, ctx.Scope) {
		return targetSkip
	}
	if len(target.DependencyTypes) > 0 && !dependencyTypesMatch(target.DependencyTypes, ctx.DependencyTypes) {
		return targetSkip
	}
	return targetApply
}

func scopeMatches(allowed []domain.DependencyScope, actual domain.DependencyScope) bool {
	for _, value := range allowed {
		if value == actual {
			return true
		}
	}
	return false
}

func dependencyTypesMatch(allowed, actual []domain.DependencyType) bool {
	for _, allowedType := range allowed {
		for _, actualType := range actual {
			if allowedType == actualType {
				return true
			}
		}
	}
	return false
}
