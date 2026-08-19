package condition

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestLicense(t *testing.T) {
	cond := License{}

	tests := []struct {
		name       string
		req        domain.AccessRequest
		config     domain.PolicyConfig
		wantMatch  bool
		wantReason string
		wantErr    bool
	}{
		{
			name: "matching SPDX license",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT", "Apache-2.0"},
				},
			},
			config:     &domain.LicensePolicyConfig{Licenses: []string{"Apache-2.0"}},
			wantMatch:  true,
			wantReason: `license "Apache-2.0"`,
		},
		{
			name: "match is case insensitive",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT"},
				},
			},
			config:     &domain.LicensePolicyConfig{Licenses: []string{"mit"}},
			wantMatch:  true,
			wantReason: `license "MIT"`,
		},
		{
			name: "no matching license",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT"},
				},
			},
			config:    &domain.LicensePolicyConfig{Licenses: []string{"GPL-3.0-only"}},
			wantMatch: false,
		},
		{
			name: "nil metadata skips",
			req: domain.AccessRequest{
				Metadata: nil,
			},
			config:    &domain.LicensePolicyConfig{Licenses: []string{"MIT"}},
			wantMatch: false,
		},
		{
			name: "missing licenses config returns error",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT"},
				},
			},
			config:  &domain.LicensePolicyConfig{},
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
			if tt.wantMatch {
				assert.Contains(t, reason, tt.wantReason)
			}
		})
	}
}

func TestLicenseAllowlist(t *testing.T) {
	cond := LicenseAllowlist{}

	tests := []struct {
		name       string
		req        domain.AccessRequest
		config     domain.PolicyConfig
		wantMatch  bool
		wantReason string
		wantErr    bool
	}{
		{
			name: "approved licenses pass",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT", "Apache-2.0"},
				},
			},
			config:    &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT", "Apache-2.0"}},
			wantMatch: false,
		},
		{
			name: "unapproved license matches",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"GPL-3.0-only"},
				},
			},
			config:     &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT"}},
			wantMatch:  true,
			wantReason: `license "GPL-3.0-only" is not in the approved license list`,
		},
		{
			name: "matching is case insensitive",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT"},
				},
			},
			config:    &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"mit"}},
			wantMatch: false,
		},
		{
			name: "missing metadata denies",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "ms",
					Version:   "0.7.1",
				},
				Metadata: nil,
			},
			config:     &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT"}},
			wantMatch:  true,
			wantReason: "license metadata is unavailable for ms@0.7.1",
		},
		{
			name: "unversioned npm metadata skips",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "react",
				},
				Metadata: nil,
			},
			config:    &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT"}},
			wantMatch: false,
		},
		{
			name: "empty licenses denies",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "legacy-package",
					Version:   "1.0.0",
				},
				Metadata: &domain.ArtifactMetadata{},
			},
			config:     &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT"}},
			wantMatch:  true,
			wantReason: "legacy-package@1.0.0 does not declare a license",
		},
		{
			name: "schema v2 can skip unavailable metadata",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "unknown-license-package",
					Version:   "1.0.0",
				},
				Metadata: nil,
			},
			config: &domain.LicenseAllowlistPolicyConfigV2{
				Licenses:                    []string{"MIT"},
				UnavailableMetadataBehavior: domain.LicenseAllowlistMissingBehaviorSkip,
			},
			wantMatch: false,
		},
		{
			name: "schema v2 can skip unlicensed artifacts",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "legacy-package",
					Version:   "1.0.0",
				},
				Metadata: &domain.ArtifactMetadata{},
			},
			config: &domain.LicenseAllowlistPolicyConfigV2{
				Licenses:           []string{"MIT"},
				UnlicensedBehavior: domain.LicenseAllowlistMissingBehaviorSkip,
			},
			wantMatch: false,
		},
		{
			name: "schema v2 can deny unlicensed artifacts explicitly",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "legacy-package",
					Version:   "1.0.0",
				},
				Metadata: &domain.ArtifactMetadata{},
			},
			config: &domain.LicenseAllowlistPolicyConfigV2{
				Licenses:           []string{"MIT"},
				UnlicensedBehavior: domain.LicenseAllowlistMissingBehaviorDeny,
			},
			wantMatch:  true,
			wantReason: "does not declare a license",
		},
		{
			name: "schema v2 rejects invalid missing-license behavior",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT"},
				},
			},
			config: &domain.LicenseAllowlistPolicyConfigV2{
				Licenses:           []string{"MIT"},
				UnlicensedBehavior: "block",
			},
			wantErr: true,
		},
		{
			name:    "allow action config type mismatch returns error",
			config:  &domain.LicensePolicyConfig{Licenses: []string{"MIT"}},
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
			if tt.wantReason != "" {
				assert.Contains(t, reason, tt.wantReason)
			}
		})
	}
}
