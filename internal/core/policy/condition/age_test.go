package condition

import (
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrTime(t time.Time) *time.Time { return &t }

func TestMinimumAge(t *testing.T) {
	cond := MinimumAge{}
	now := time.Now()

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    map[string]any
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
			config:    map[string]any{"min_age_days": 30.0},
			wantMatch: false,
		},
		{
			name: "too new, match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now.Add(-2 * 24 * time.Hour)),
				},
			},
			config:    map[string]any{"min_age_days": 30.0},
			wantMatch: true,
		},
		{
			name: "nil PublishedAt, no match",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{PublishedAt: nil},
			},
			config:    map[string]any{"min_age_days": 30.0},
			wantMatch: false,
		},
		{
			name: "nil metadata, no match",
			req: domain.AccessRequest{
				Metadata: nil,
			},
			config:    map[string]any{"min_age_days": 30.0},
			wantMatch: false,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Metadata: &domain.ArtifactMetadata{
					PublishedAt: ptrTime(now),
				},
			},
			config:  map[string]any{},
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
				assert.Contains(t, reason, "minimum required")
			}
		})
	}
}
