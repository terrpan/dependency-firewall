package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func hashPtrFloat64(v float64) *float64 { return &v }
func hashPtrInt(v int) *int             { return &v }

func TestHashPolicies_IsStableForEquivalentPolicies(t *testing.T) {
	first, err := HashPolicies([]domain.Policy{
		{
			Name:     "block-critical",
			Type:     domain.PolicyTypeCVSSThreshold,
			Action:   domain.PolicyActionDeny,
			Priority: 10,
			Enabled:  true,
			Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: hashPtrFloat64(7.0)},
		},
		{
			Name:     "block-old",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Priority: 20,
			Enabled:  true,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: hashPtrInt(365), ExcludePackages: []string{"unpipe"}},
		},
	})
	require.NoError(t, err)

	second, err := HashPolicies([]domain.Policy{
		{
			Name:     "block-old",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Priority: 20,
			Enabled:  true,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: hashPtrInt(365), ExcludePackages: []string{"unpipe"}},
		},
		{
			Name:     "block-critical",
			Type:     domain.PolicyTypeCVSSThreshold,
			Action:   domain.PolicyActionDeny,
			Priority: 10,
			Enabled:  true,
			Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: hashPtrFloat64(7.0)},
		},
	})
	require.NoError(t, err)

	assert.Equal(t, first, second)
}

func TestHashPolicies_ChangesWhenPolicyStateChanges(t *testing.T) {
	base := []domain.Policy{
		{
			Name:     "block-old",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Priority: 20,
			Enabled:  true,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: hashPtrInt(365)},
		},
	}

	first, err := HashPolicies(base)
	require.NoError(t, err)

	second, err := HashPolicies([]domain.Policy{
		{
			Name:     "block-old",
			Type:     domain.PolicyTypeMaximumAge,
			Action:   domain.PolicyActionDeny,
			Priority: 20,
			Enabled:  false,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: hashPtrInt(365)},
		},
	})
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
}
