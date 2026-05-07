package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScorecardPolicyConfigValidate(t *testing.T) {
	t.Run("requires at least one threshold", func(t *testing.T) {
		config := &ScorecardPolicyConfig{}
		err := config.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `at least one of "min_score" or "checks" is required`)
	})

	t.Run("normalizes check names", func(t *testing.T) {
		config := &ScorecardPolicyConfig{
			Checks: map[string]float64{
				"Binary Artifacts":  10,
				"Branch_Protection": 7,
			},
		}
		require.NoError(t, config.Validate())
		assert.Equal(t, map[string]float64{
			"binary-artifacts":  10,
			"branch-protection": 7,
		}, config.Checks)
	})

	t.Run("rejects duplicate normalized check names", func(t *testing.T) {
		config := &ScorecardPolicyConfig{
			Checks: map[string]float64{
				"Binary Artifacts": 10,
				"binary-artifacts": 9,
			},
		}
		err := config.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `duplicate scorecard check threshold "binary-artifacts"`)
	})

	t.Run("rejects out of range scores", func(t *testing.T) {
		config := &ScorecardPolicyConfig{
			MinScore: ptrFloat64(11),
		}
		err := config.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid config value for "min_score": must be between 0 and 10`)
	})

	t.Run("defaults unavailable behavior to deny", func(t *testing.T) {
		config := &ScorecardPolicyConfig{
			MinScore: ptrFloat64(7),
		}
		require.NoError(t, config.Validate())
		assert.Equal(t, ScorecardUnavailableBehaviorDeny, config.EffectiveUnavailableScorecardBehavior())
	})
}

func ptrFloat64(v float64) *float64 {
	return &v
}
