package condition

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// BlockMutableTag matches when the artifact uses a mutable tag that is in the blocked list.
type BlockMutableTag struct{}

// Evaluate checks whether the artifact's version is a blocked mutable tag.
func (b BlockMutableTag) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.BlockMutableTagPolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("block_mutable_tag requires %T, got %T", &domain.BlockMutableTagPolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	if req.Metadata == nil || !req.Metadata.IsMutableTag {
		return false, "", nil
	}

	version := req.Artifact.Version
	for _, tag := range typed.Tags {
		if version == tag {
			return true, fmt.Sprintf("mutable tag %q is blocked by policy", tag), nil
		}
	}

	return false, "", nil
}
