package condition

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestScorecardEvaluate(t *testing.T) {
	req := domain.AccessRequest{
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "left-pad",
			Version:   "1.3.0",
		},
		Metadata: &domain.ArtifactMetadata{
			SourceRepository: &domain.SourceRepository{
				Host:  "github.com",
				Owner: "acme",
				Repo:  "left-pad",
			},
			Scorecard: &domain.ScorecardResult{
				Score: ptrScore(6.5),
				Checks: map[string]float64{
					"binary-artifacts":  10,
					"branch-protection": 5,
				},
			},
		},
	}

	t.Run("matches when overall score is below threshold", func(t *testing.T) {
		matched, reason, err := Scorecard{}.Evaluate(req, &domain.ScorecardPolicyConfig{
			MinScore: ptrScore(7),
		})
		require.NoError(t, err)
		assert.True(t, matched)
		assert.Contains(t, reason, "Scorecard 6.5 is below minimum 7.0")
	})

	t.Run("matches when a configured check is below threshold", func(t *testing.T) {
		matched, reason, err := Scorecard{}.Evaluate(req, &domain.ScorecardPolicyConfig{
			Checks: map[string]float64{
				"Branch Protection": 7,
			},
		})
		require.NoError(t, err)
		assert.True(t, matched)
		assert.Contains(t, reason, `check "branch-protection" scored 5.0 below minimum 7.0`)
	})

	t.Run("skips when scorecard is unavailable and behavior is skip", func(t *testing.T) {
		matched, reason, err := Scorecard{}.Evaluate(domain.AccessRequest{
			Artifact: req.Artifact,
			Metadata: &domain.ArtifactMetadata{
				SourceRepository: req.Metadata.SourceRepository,
				Scorecard: &domain.ScorecardResult{
					UnavailableReason: "Scorecard data is unavailable for github.com/acme/left-pad",
				},
			},
		}, &domain.ScorecardPolicyConfig{
			MinScore:                     ptrScore(7),
			UnavailableScorecardBehavior: domain.ScorecardUnavailableBehaviorSkip,
		})
		require.NoError(t, err)
		assert.False(t, matched)
		assert.Empty(t, reason)
	})

	t.Run("denies when a required check is unavailable", func(t *testing.T) {
		matched, reason, err := Scorecard{}.Evaluate(domain.AccessRequest{
			Artifact: req.Artifact,
			Metadata: &domain.ArtifactMetadata{
				SourceRepository: req.Metadata.SourceRepository,
				Scorecard: &domain.ScorecardResult{
					Score:  ptrScore(8.2),
					Checks: map[string]float64{"maintained": 10},
				},
			},
		}, &domain.ScorecardPolicyConfig{
			Checks: map[string]float64{
				"binary-artifacts": 10,
			},
		})
		require.NoError(t, err)
		assert.True(t, matched)
		assert.Contains(t, reason, `Scorecard check "binary-artifacts" is unavailable`)
	})

	t.Run("treats negative check scores as unavailable", func(t *testing.T) {
		matched, reason, err := Scorecard{}.Evaluate(domain.AccessRequest{
			Artifact: req.Artifact,
			Metadata: &domain.ArtifactMetadata{
				SourceRepository: req.Metadata.SourceRepository,
				Scorecard: &domain.ScorecardResult{
					Score: ptrScore(8.2),
					Checks: map[string]float64{
						"branch-protection": -1,
					},
				},
			},
		}, &domain.ScorecardPolicyConfig{
			Checks: map[string]float64{
				"branch-protection": 7,
			},
			UnavailableScorecardBehavior: domain.ScorecardUnavailableBehaviorSkip,
		})
		require.NoError(t, err)
		assert.False(t, matched)
		assert.Empty(t, reason)
	})
}

func ptrScore(v float64) *float64 {
	return &v
}
