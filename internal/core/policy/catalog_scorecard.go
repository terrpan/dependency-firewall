package policy

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func scorecardPolicyDefinition() policyDefinition {
	return definePolicy(
		domain.PolicyTypeDescriptor{
			Type:                    domain.PolicyTypeScorecard,
			Summary:                 "Gate by OpenSSF Scorecard",
			Description:             "Matches npm artifacts whose source repository Scorecard falls below the configured overall or per-check thresholds.",
			Help:                    "Use this to require a minimum repository Scorecard before allowing a package. It can deny on the overall score, named check scores, or both. When repository identity or Scorecard data is unavailable, the configured behavior decides whether the policy denies or skips.",
			CurrentSchemaVersion:    1,
			SupportedSchemaVersions: []int{1},
			SupportedActions:        []domain.PolicyAction{domain.PolicyActionDeny},
			SupportedEcosystems:     []domain.EcosystemType{domain.EcosystemNPM},
			RequiredCapabilities:    []domain.UpstreamCapability{domain.UpstreamCapabilityScorecardLookup},
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
		true,
		configTypeMatcher[*domain.ScorecardPolicyConfig],
		configSchema(1, func() domain.PolicyConfig { return &domain.ScorecardPolicyConfig{} }),
	)
}
