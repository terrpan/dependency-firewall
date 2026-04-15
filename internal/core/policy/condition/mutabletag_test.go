package condition

import (
	"testing"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockMutableTag(t *testing.T) {
	cond := BlockMutableTag{}

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    map[string]any
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "mutable tag latest blocked, match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Version: "latest"},
				Metadata: &domain.ArtifactMetadata{IsMutableTag: true},
			},
			config:    map[string]any{"tags": []string{"latest"}},
			wantMatch: true,
		},
		{
			name: "non-mutable digest ref, no match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Version: "latest", Digest: "sha256:abc123"},
				Metadata: &domain.ArtifactMetadata{IsMutableTag: false},
			},
			config:    map[string]any{"tags": []string{"latest"}},
			wantMatch: false,
		},
		{
			name: "tag not in blocked list, no match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Version: "v1.0.0"},
				Metadata: &domain.ArtifactMetadata{IsMutableTag: true},
			},
			config:    map[string]any{"tags": []string{"latest"}},
			wantMatch: false,
		},
		{
			name: "nil metadata, no match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Version: "latest"},
				Metadata: nil,
			},
			config:    map[string]any{"tags": []string{"latest"}},
			wantMatch: false,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Version: "latest"},
				Metadata: &domain.ArtifactMetadata{IsMutableTag: true},
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
				assert.Contains(t, reason, "blocked by policy")
			}
		})
	}
}
