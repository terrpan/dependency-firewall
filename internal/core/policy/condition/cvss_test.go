package condition

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func ptrFloat64(v float64) *float64                            { return &v }
func ptrSeverity(v domain.SeverityLevel) *domain.SeverityLevel { return &v }

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
			name: "severity-only config matches vulnerability severity",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Vulnerabilities: []domain.Vulnerability{
						{ID: "CVE-2024-1001", Severity: "high", CVSS: 8.2},
					},
				},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MinimumSeverity: ptrSeverity(domain.SeverityHigh)},
			wantMatch: true,
		},
		{
			name: "severity matching is case-insensitive",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Vulnerabilities: []domain.Vulnerability{
						{ID: "CVE-2024-1002", Severity: "HIGH", CVSS: 8.0},
					},
				},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MinimumSeverity: ptrSeverity(domain.SeverityHigh)},
			wantMatch: true,
		},
		{
			name: "severity inferred from CVSS when severity string is missing",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Vulnerabilities: []domain.Vulnerability{
						{ID: "CVE-2024-1003", Severity: "", CVSS: 9.3},
					},
				},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MinimumSeverity: ptrSeverity(domain.SeverityCritical)},
			wantMatch: true,
		},
		{
			name: "severity threshold not met",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Vulnerabilities: []domain.Vulnerability{
						{ID: "CVE-2024-1004", Severity: "medium", CVSS: 5.5},
					},
				},
			},
			config:    &domain.CVSSThresholdPolicyConfig{MinimumSeverity: ptrSeverity(domain.SeverityHigh)},
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
