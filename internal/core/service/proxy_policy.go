package service

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

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
		if policyDef.Enabled && corepolicy.RequiresExternalMetadata(policyDef.Type) {
			return true
		}
	}
	return false
}

func needsDependencyContext(policies []domain.Policy) bool {
	for _, policyDef := range policies {
		if policyDef.Enabled && policyDef.Target != nil {
			return true
		}
	}
	return false
}

func shouldEnrichArtifact(req domain.AccessRequest, policies []domain.Policy) bool {
	if isUnversionedNPMArtifact(req.Artifact) {
		return false
	}
	return needsEnrichment(policies)
}

func shouldCacheDecision(req domain.AccessRequest) bool {
	return !isUnversionedNPMArtifact(req.Artifact)
}

func shouldPersistDecision(req domain.AccessRequest, decision *domain.Decision) bool {
	return !(isUnversionedNPMArtifact(req.Artifact) && decision.Outcome == domain.DecisionAllow)
}

func isUnversionedNPMArtifact(artifact domain.ArtifactIdentity) bool {
	return artifact.Ecosystem == domain.EcosystemNPM && artifact.Version == ""
}
