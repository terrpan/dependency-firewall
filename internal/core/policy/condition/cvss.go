package condition

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// CVSSThreshold matches when the artifact's max CVSS score is at or above a threshold.
type CVSSThreshold struct{}

// Evaluate checks whether the artifact's max CVSS score is at or above max_cvss from config.
func (c CVSSThreshold) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.CVSSThresholdPolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("cvss_threshold requires %T, got %T", &domain.CVSSThresholdPolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	if req.Metadata == nil || req.Metadata.MaxCVSS == nil {
		return false, "", nil
	}

	score := *req.Metadata.MaxCVSS
	if score >= *typed.MaxCVSS {
		return true, fmt.Sprintf("artifact has CVSS score %.1f at or above threshold %.1f", score, *typed.MaxCVSS), nil
	}

	return false, "", nil
}
