package condition

import (
	"testing"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrFloat64(v float64) *float64 { return &v }

func TestCVSSThreshold(t *testing.T) {
	cond := CVSSThreshold{}

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    domain.PolicyConfig
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "below threshold, no match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{MaxCVSS: ptrFloat64(5.0)},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
			wantMatch: false,
		},
		{
			name: "at threshold, match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{MaxCVSS: ptrFloat64(7.0)},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
			wantMatch: true,
		},
		{
			name: "above threshold, match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{MaxCVSS: ptrFloat64(9.1)},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
			wantMatch: true,
		},
		{
			name: "nil metadata, no match",
			req: domain.AccessRequest{
				Metadata: nil,
			},
			config:    &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
			wantMatch: false,
		},
		{
			name: "nil MaxCVSS, no match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{MaxCVSS: nil},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
			wantMatch: false,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{MaxCVSS: ptrFloat64(9.0)},
			},
			config:  &domain.CVSSThresholdPolicyConfig{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, reason, err := cond.Evaluate(tt.req, tt.config)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMatch, matched)
			if matched {
				assert.NotEmpty(t, reason)
			}
		})
	}
}
