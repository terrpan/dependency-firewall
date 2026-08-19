package condition

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Scorecard matches when the source repository Scorecard falls below the
// configured overall or per-check thresholds.
type Scorecard struct{}

// Evaluate checks the hosted Scorecard metadata against the configured policy.
func (s Scorecard) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.ScorecardPolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("scorecard requires %T, got %T", &domain.ScorecardPolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	scorecard := scorecardResult(req.Metadata)
	if scorecard == nil {
		return applyUnavailableScorecardBehavior(
			typed.EffectiveUnavailableScorecardBehavior(),
			scorecardUnavailableReason(req, ""),
		)
	}

	if typed.MinScore != nil {
		if scorecard.Score == nil {
			return applyUnavailableScorecardBehavior(
				typed.EffectiveUnavailableScorecardBehavior(),
				scorecardUnavailableReason(req, "overall Scorecard is unavailable"),
			)
		}
		if *scorecard.Score < *typed.MinScore {
			return true, fmt.Sprintf(
				"source repository Scorecard %.1f is below minimum %.1f",
				*scorecard.Score,
				*typed.MinScore,
			), nil
		}
	}

	if len(typed.Checks) == 0 {
		return false, "", nil
	}

	checkNames := make([]string, 0, len(typed.Checks))
	for name := range typed.Checks {
		checkNames = append(checkNames, name)
	}
	sort.Strings(checkNames)

	for _, checkName := range checkNames {
		minScore := typed.Checks[checkName]
		actualScore, ok := scorecard.Checks[checkName]
		if !ok {
			return applyUnavailableScorecardBehavior(
				typed.EffectiveUnavailableScorecardBehavior(),
				scorecardUnavailableReason(req, fmt.Sprintf("Scorecard check %q is unavailable", checkName)),
			)
		}
		if actualScore < 0 {
			return applyUnavailableScorecardBehavior(
				typed.EffectiveUnavailableScorecardBehavior(),
				scorecardUnavailableReason(req, fmt.Sprintf("Scorecard check %q is unavailable", checkName)),
			)
		}
		if actualScore < minScore {
			return true, fmt.Sprintf(
				"source repository Scorecard check %q scored %.1f below minimum %.1f",
				checkName,
				actualScore,
				minScore,
			), nil
		}
	}

	return false, "", nil
}

func applyUnavailableScorecardBehavior(
	behavior domain.ScorecardUnavailableBehavior,
	reason string,
) (bool, string, error) {
	if behavior == domain.ScorecardUnavailableBehaviorSkip {
		return false, "", nil
	}
	return true, reason, nil
}

func scorecardResult(metadata *domain.ArtifactMetadata) *domain.ScorecardResult {
	if metadata == nil {
		return nil
	}
	return metadata.Scorecard
}

func scorecardUnavailableReason(req domain.AccessRequest, detail string) string {
	ref := scorecardReference(req.Metadata, req.Artifact)
	scorecard := scorecardResult(req.Metadata)
	if scorecard != nil && strings.TrimSpace(scorecard.UnavailableReason) != "" {
		return fmt.Sprintf(
			"%s and Scorecard policy denies the artifact",
			strings.TrimSpace(scorecard.UnavailableReason),
		)
	}

	switch {
	case detail != "" && ref != "":
		return fmt.Sprintf("%s for %s and Scorecard policy denies the artifact", detail, ref)
	case detail != "":
		return fmt.Sprintf("%s and Scorecard policy denies the artifact", detail)
	case ref != "":
		return fmt.Sprintf("Scorecard data is unavailable for %s and Scorecard policy denies the artifact", ref)
	default:
		return "Scorecard data is unavailable and Scorecard policy denies the artifact"
	}
}

func scorecardReference(metadata *domain.ArtifactMetadata, artifact domain.ArtifactIdentity) string {
	if metadata != nil && metadata.SourceRepository != nil {
		if projectURI := metadata.SourceRepository.ProjectURI(); projectURI != "" {
			return projectURI
		}
		if displayName := metadata.SourceRepository.DisplayName(); displayName != "" {
			return displayName
		}
	}

	ref := artifact.FullName()
	switch {
	case strings.TrimSpace(artifact.Digest) != "":
		return ref + "@" + strings.TrimSpace(artifact.Digest)
	case strings.TrimSpace(artifact.Version) != "":
		return ref + "@" + strings.TrimSpace(artifact.Version)
	default:
		return ref
	}
}
