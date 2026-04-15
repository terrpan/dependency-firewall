package condition

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// BlockMutableTag matches when the artifact uses a mutable tag that is in the blocked list.
type BlockMutableTag struct{}

// Evaluate checks whether the artifact's version is a blocked mutable tag.
func (b BlockMutableTag) Evaluate(req domain.AccessRequest, config map[string]any) (bool, string, error) {
	raw, ok := config["tags"]
	if !ok {
		return false, "", fmt.Errorf("missing required config key \"tags\"")
	}

	tags, ok := toStringSlice(raw)
	if !ok {
		return false, "", fmt.Errorf("config key \"tags\" must be a list of strings")
	}

	if req.Metadata == nil || !req.Metadata.IsMutableTag {
		return false, "", nil
	}

	version := req.Artifact.Version
	for _, tag := range tags {
		if version == tag {
			return true, fmt.Sprintf("mutable tag %q is blocked by policy", tag), nil
		}
	}

	return false, "", nil
}

func toStringSlice(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			str, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, str)
		}
		return result, true
	default:
		return nil, false
	}
}
