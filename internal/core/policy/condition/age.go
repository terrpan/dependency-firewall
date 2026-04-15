package condition

import (
	"fmt"
	"math"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// MinimumAge matches when an artifact was published fewer than min_age_days ago.
type MinimumAge struct{}

// Evaluate checks whether the artifact was published fewer than min_age_days ago.
func (m MinimumAge) Evaluate(req domain.AccessRequest, config map[string]any) (bool, string, error) {
	raw, ok := config["min_age_days"]
	if !ok {
		return false, "", fmt.Errorf("missing required config key \"min_age_days\"")
	}

	minDays, ok := toFloat64(raw)
	if !ok {
		return false, "", fmt.Errorf("config key \"min_age_days\" must be a number")
	}

	if req.Metadata == nil || req.Metadata.PublishedAt == nil {
		return false, "", nil
	}

	ageDays := time.Since(*req.Metadata.PublishedAt).Hours() / 24
	ageDaysRounded := int(math.Floor(ageDays))

	if ageDays < minDays {
		return true, fmt.Sprintf("artifact published %d days ago, minimum required is %d days", ageDaysRounded, int(minDays)), nil
	}

	return false, "", nil
}
