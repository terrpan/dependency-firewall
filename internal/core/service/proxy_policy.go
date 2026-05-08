package service

import "github.com/danielterry/dependency-firewall/internal/core/domain"

func filterPoliciesForUpstream(policies []domain.Policy, upstreamID string) []domain.Policy {
	if upstreamID == "" {
		return policies
	}

	filtered := make([]domain.Policy, 0, len(policies))
	for _, policyDef := range policies {
		if policyDef.UpstreamID != "" && policyDef.UpstreamID != upstreamID {
			continue
		}
		filtered = append(filtered, policyDef)
	}
	return filtered
}

func needsEnrichment(policies []domain.Policy) bool {
	for _, policyDef := range policies {
		if policyDef.Enabled && policyNeedsEnrichment(policyDef.Type) {
			return true
		}
	}
	return false
}

func policyNeedsEnrichment(policyType domain.PolicyType) bool {
	switch policyType {
	case domain.PolicyTypeMinimumAge,
		domain.PolicyTypeMaximumAge,
		domain.PolicyTypeLicense,
		domain.PolicyTypeLicenseAllowlist,
		domain.PolicyTypeCVSSThreshold,
		domain.PolicyTypeScorecard:
		return true
	default:
		return false
	}
}
