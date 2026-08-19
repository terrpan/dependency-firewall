package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestDecodeStoredConfigJSON(t *testing.T) {
	t.Run("stored deprecated enforce returns upgrade error", func(t *testing.T) {
		_, err := DecodeStoredConfigJSON(
			domain.PolicyTypeMaximumAge,
			1,
			[]byte(`{"max_age_days":730,"enforce":"warn"}`),
		)
		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrDeprecatedPolicyConfig)
		assert.Contains(t, err.Error(), "run the policy data migration")
	})

	t.Run("stored dry_run config still decodes", func(t *testing.T) {
		cfg, err := DecodeStoredConfigJSON(
			domain.PolicyTypeMaximumAge,
			1,
			[]byte(`{"max_age_days":730,"dry_run":true}`),
		)
		require.NoError(t, err)
		typed, ok := cfg.(*domain.MaximumAgePolicyConfig)
		require.True(t, ok)
		require.NotNil(t, typed.MaxAgeDays)
		assert.Equal(t, 730, *typed.MaxAgeDays)
		assert.True(t, typed.DryRun)
	})
}

func TestToDomainPolicies_RejectsUnsupportedSchemaVersion(t *testing.T) {
	pf := &File{
		TenantID: "tenant-1",
		Policies: []Def{{
			Name:          "block-critical",
			Type:          "cvss_threshold",
			SchemaVersion: intPtr(2),
			Action:        "deny",
			Config:        map[string]any{"max_cvss": 9.0},
		}},
	}

	_, err := ToDomainPolicies(pf)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrUnsupportedPolicySchemaVersion)
}

func intPtr(v int) *int { return &v }
