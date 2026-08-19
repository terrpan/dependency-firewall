package condition

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func ptrTime(t time.Time) *time.Time { return &t }
func ptrInt(v int) *int              { return &v }

func TestMinimumAge(t *testing.T) {
	cond := MinimumAge{}
	now := time.Now()

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    domain.PolicyConfig
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "old enough, no match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-60 * 24 * time.Hour)),
				},
			},
			config:    &domain.MinimumAgePolicyConfig{MinAgeDays: ptrInt(30)},
			wantMatch: false,
		},
		{
			name: "too new, match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-2 * 24 * time.Hour)),
				},
			},
			config:    &domain.MinimumAgePolicyConfig{MinAgeDays: ptrInt(30)},
			wantMatch: true,
		},
		{
			name: "nil PublishedAt, no match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{PublishedAt: nil},
			},
			config:    &domain.MinimumAgePolicyConfig{MinAgeDays: ptrInt(30)},
			wantMatch: false,
		},
		{
			name: "nil metadata, no match",
			req: domain.AccessRequest{
				Metadata: nil,
			},
			config:    &domain.MinimumAgePolicyConfig{MinAgeDays: ptrInt(30)},
			wantMatch: false,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now),
				},
			},
			config:  &domain.MinimumAgePolicyConfig{},
			wantErr: true,
		},
		{
			name: "excluded package skips check",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Name: "my-pkg"},
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-1 * 24 * time.Hour)),
				},
			},
			config: &domain.MinimumAgePolicyConfig{
				MinAgeDays:      ptrInt(30),
				ExcludePackages: []string{"my-pkg"},
			},
			wantMatch: false,
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
				assert.Contains(t, reason, "minimum required")
			}
		})
	}
}

func TestMaximumAge(t *testing.T) {
	cond := MaximumAge{}
	now := time.Now()

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    domain.PolicyConfig
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "recent package, no match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-30 * 24 * time.Hour)),
				},
			},
			config:    &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365)},
			wantMatch: false,
		},
		{
			name: "too old, match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-400 * 24 * time.Hour)),
				},
			},
			config:    &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365)},
			wantMatch: true,
		},
		{
			name: "exactly at boundary (just over), match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-366 * 24 * time.Hour)),
				},
			},
			config:    &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365)},
			wantMatch: true,
		},
		{
			name: "nil PublishedAt, no match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{PublishedAt: nil},
			},
			config:    &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365)},
			wantMatch: false,
		},
		{
			name: "nil metadata, no match",
			req: domain.AccessRequest{
				Metadata: nil,
			},
			config:    &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365)},
			wantMatch: false,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now),
				},
			},
			config:  &domain.MaximumAgePolicyConfig{},
			wantErr: true,
		},
		{
			name: "invalid config type, error",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now),
				},
			},
			config:  &domain.MaximumAgePolicyConfig{},
			wantErr: true,
		},
		{
			name: "excluded package skips check",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Name: "unpipe"},
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-4000 * 24 * time.Hour)),
				},
			},
			config: &domain.MaximumAgePolicyConfig{
				MaxAgeDays:      ptrInt(365),
				ExcludePackages: []string{"unpipe", "ee-first"},
			},
			wantMatch: false,
		},
		{
			name: "excluded scoped package skips check",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "@types", Name: "node"},
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-4000 * 24 * time.Hour)),
				},
			},
			config: &domain.MaximumAgePolicyConfig{
				MaxAgeDays:      ptrInt(365),
				ExcludePackages: []string{"@types/node"},
			},
			wantMatch: false,
		},
		{
			name: "non-excluded package still blocked",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Name: "other-pkg"},
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-4000 * 24 * time.Hour)),
				},
			},
			config: &domain.MaximumAgePolicyConfig{
				MaxAgeDays:      ptrInt(365),
				ExcludePackages: []string{"unpipe"},
			},
			wantMatch: true,
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
				assert.Contains(t, reason, "maximum allowed")
			}
		})
	}
}
