package condition

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// CVSSThreshold matches when the artifact's max CVSS score exceeds a threshold.
type CVSSThreshold struct{}

// Evaluate checks whether the artifact's max CVSS score exceeds max_cvss from config.
func (c CVSSThreshold) Evaluate(req domain.AccessRequest, config map[string]any) (bool, string, error) {
	raw, ok := config["max_cvss"]
	if !ok {
		return false, "", fmt.Errorf("missing required config key \"max_cvss\"")
	}

	threshold, ok := toFloat64(raw)
	if !ok {
		return false, "", fmt.Errorf("config key \"max_cvss\" must be a number")
	}

	if req.Metadata == nil || req.Metadata.MaxCVSS == nil {
		return false, "", nil
	}

	score := *req.Metadata.MaxCVSS
	if score > threshold {
		return true, fmt.Sprintf("artifact has CVSS score %.1f exceeding threshold %.1f", score, threshold), nil
	}

	return false, "", nil
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
