package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func scorecardPolicyDefinition() policyDefinition {
	return defineDenyPolicyV1(
		domain.PolicyTypeDescriptor{
			Type:        domain.PolicyTypeScorecard,
			Summary:     "Gate by OpenSSF Scorecard",
			Description: "Matches npm artifacts whose source repository Scorecard falls below the configured overall or per-check thresholds.",
			Help:        "Use this to require a minimum repository Scorecard before allowing a package. It can deny on the overall score, named check scores, or both. When repository identity or Scorecard data is unavailable, the configured behavior decides whether the policy denies or skips.",
			Example: `- name: require-secure-source-repos
  type: scorecard
  schema_version: 1
  action: deny
  priority: 15
  config:
    min_score: 7
    checks:
      binary-artifacts: 10
      branch-protection: 7
    unavailable_scorecard_behavior: skip`,
		},
		condition.Scorecard{},
		domain.EcosystemNPM,
		domain.UpstreamCapabilityScorecardLookup,
		true,
		func() *domain.ScorecardPolicyConfig { return &domain.ScorecardPolicyConfig{} },
	)
}
