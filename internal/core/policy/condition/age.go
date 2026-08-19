package condition

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// MinimumAge matches when an artifact was published fewer than min_age_days ago.
type MinimumAge struct{}

// Evaluate checks whether the artifact was published fewer than min_age_days ago.
func (m MinimumAge) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.MinimumAgePolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("minimum_age requires %T, got %T", &domain.MinimumAgePolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	return evaluateAge(
		req,
		typed.ExcludePackages,
		*typed.MinAgeDays,
		isYoungerThan,
		"artifact published %d days ago, minimum required is %d days",
	)
}

// MaximumAge matches when an artifact was published more than max_age_days ago.
type MaximumAge struct{}

// Evaluate checks whether the artifact was published more than max_age_days ago.
func (m MaximumAge) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.MaximumAgePolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("maximum_age requires %T, got %T", &domain.MaximumAgePolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	return evaluateAge(
		req,
		typed.ExcludePackages,
		*typed.MaxAgeDays,
		isOlderThan,
		"artifact published %d days ago, maximum allowed is %d days",
	)
}

func evaluateAge(
	req domain.AccessRequest,
	excludedPackages []string,
	thresholdDays int,
	matches func(float64, int) bool,
	reasonFormat string,
) (bool, string, error) {
	if isExcludedPackage(req.Artifact.FullName(), excludedPackages) {
		return false, "", nil
	}
	if req.Metadata == nil || req.Metadata.PublishedAt == nil {
		return false, "", nil
	}

	ageDays := time.Since(*req.Metadata.PublishedAt).Hours() / 24
	if !matches(ageDays, thresholdDays) {
		return false, "", nil
	}

	return true, fmt.Sprintf(reasonFormat, int(math.Floor(ageDays)), thresholdDays), nil
}

func isYoungerThan(ageDays float64, thresholdDays int) bool {
	return ageDays < float64(thresholdDays)
}

func isOlderThan(ageDays float64, thresholdDays int) bool {
	return ageDays > float64(thresholdDays)
}

// isExcludedPackage checks if the artifact's full name is in the exclude_packages list.
func isExcludedPackage(fullName string, excluded []string) bool {
	return slices.Contains(excluded, fullName)
}
