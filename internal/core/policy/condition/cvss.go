package condition

import (
	"fmt"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// CVSSThreshold matches when the artifact's max CVSS score or minimum severity is at or above a threshold.
type CVSSThreshold struct{}

// Evaluate checks whether the artifact's max CVSS score or minimum severity is at or above the threshold.
func (c CVSSThreshold) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.CVSSThresholdPolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("cvss_threshold requires %T, got %T", &domain.CVSSThresholdPolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	if req.Metadata == nil {
		return false, "", nil
	}

	if typed.MaxCVSS != nil && req.Metadata.MaxCVSS != nil {
		score := *req.Metadata.MaxCVSS
		if score >= *typed.MaxCVSS {
			return true, fmt.Sprintf("artifact has CVSS score %.1f at or above threshold %.1f", score, *typed.MaxCVSS), nil
		}
	}

	if typed.MinimumSeverity != nil {
		threshold := normalizeSeverity(*typed.MinimumSeverity)
		for _, vulnerability := range req.Metadata.Vulnerabilities {
			actual := normalizeSeverity(domain.SeverityLevel(vulnerability.Severity))
			inferredFromScore := false
			if actual == "" {
				actual = severityFromCVSS(vulnerability.CVSS)
				inferredFromScore = actual != ""
			}

			if severityAtOrAbove(actual, threshold) {
				if inferredFromScore {
					return true, fmt.Sprintf("artifact has vulnerability with inferred severity %s (CVSS %.1f) at or above threshold %s", actual, vulnerability.CVSS, threshold), nil
				}
				return true, fmt.Sprintf("artifact has vulnerability with severity %s at or above threshold %s", actual, threshold), nil
			}
		}
	}

	return false, "", nil
}

func severityAtOrAbove(actual, threshold domain.SeverityLevel) bool {
	actualRank, actualOK := severityRank(actual)
	thresholdRank, thresholdOK := severityRank(threshold)
	return actualOK && thresholdOK && actualRank >= thresholdRank
}

func severityRank(severity domain.SeverityLevel) (int, bool) {
	switch normalizeSeverity(severity) {
	case domain.SeverityNone:
		return 0, true
	case domain.SeverityLow:
		return 1, true
	case domain.SeverityMedium:
		return 2, true
	case domain.SeverityHigh:
		return 3, true
	case domain.SeverityCritical:
		return 4, true
	default:
		return 0, false
	}
}

func normalizeSeverity(severity domain.SeverityLevel) domain.SeverityLevel {
	normalized := domain.SeverityLevel(strings.ToLower(strings.TrimSpace(string(severity))))
	if _, ok := severityRankWithoutNormalization(normalized); ok {
		return normalized
	}
	return ""
}

func severityRankWithoutNormalization(severity domain.SeverityLevel) (int, bool) {
	switch severity {
	case domain.SeverityNone:
		return 0, true
	case domain.SeverityLow:
		return 1, true
	case domain.SeverityMedium:
		return 2, true
	case domain.SeverityHigh:
		return 3, true
	case domain.SeverityCritical:
		return 4, true
	default:
		return 0, false
	}
}

func severityFromCVSS(score float64) domain.SeverityLevel {
	switch {
	case score >= 9.0:
		return domain.SeverityCritical
	case score >= 7.0:
		return domain.SeverityHigh
	case score >= 4.0:
		return domain.SeverityMedium
	case score > 0:
		return domain.SeverityLow
	default:
		return ""
	}
}
