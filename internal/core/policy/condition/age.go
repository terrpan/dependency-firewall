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

	if isExcludedPackage(req.Artifact.FullName(), typed.ExcludePackages) {
		return false, "", nil
	}

	if req.Metadata == nil || req.Metadata.PublishedAt == nil {
		return false, "", nil
	}

	ageDays := time.Since(*req.Metadata.PublishedAt).Hours() / 24
	ageDaysRounded := int(math.Floor(ageDays))

	if ageDays < float64(*typed.MinAgeDays) {
		return true, fmt.Sprintf(
			"artifact published %d days ago, minimum required is %d days",
			ageDaysRounded,
			*typed.MinAgeDays,
		), nil
	}

	return false, "", nil
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

	if isExcludedPackage(req.Artifact.FullName(), typed.ExcludePackages) {
		return false, "", nil
	}

	if req.Metadata == nil || req.Metadata.PublishedAt == nil {
		return false, "", nil
	}

	ageDays := time.Since(*req.Metadata.PublishedAt).Hours() / 24
	ageDaysRounded := int(math.Floor(ageDays))

	if ageDays > float64(*typed.MaxAgeDays) {
		return true, fmt.Sprintf(
			"artifact published %d days ago, maximum allowed is %d days",
			ageDaysRounded,
			*typed.MaxAgeDays,
		), nil
	}

	return false, "", nil
}

// isExcludedPackage checks if the artifact's full name is in the exclude_packages list.
func isExcludedPackage(fullName string, excluded []string) bool {
	return slices.Contains(excluded, fullName)
}
