package condition

import (
	"testing"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowlist(t *testing.T) {
	cond := Allowlist{}

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    domain.PolicyConfig
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "namespace in allowlist, match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "internal"},
			},
			config:    &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal", "company"}},
			wantMatch: true,
		},
		{
			name: "namespace not in allowlist, no match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "external"},
			},
			config:    &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal", "company"}},
			wantMatch: false,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "internal"},
			},
			config:  &domain.NamespaceListPolicyConfig{},
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
				assert.Contains(t, reason, "allowed")
			}
		})
	}
}

func TestBlocklist(t *testing.T) {
	cond := Blocklist{}

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    domain.PolicyConfig
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "namespace in blocklist, match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "untrusted"},
			},
			config:    &domain.NamespaceListPolicyConfig{Namespaces: []string{"untrusted", "malicious"}},
			wantMatch: true,
		},
		{
			name: "namespace not in blocklist, no match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "trusted"},
			},
			config:    &domain.NamespaceListPolicyConfig{Namespaces: []string{"untrusted", "malicious"}},
			wantMatch: false,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "untrusted"},
			},
			config:  &domain.NamespaceListPolicyConfig{},
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
				assert.Contains(t, reason, "blocked")
			}
		})
	}
}

func TestNamespaceAllowlist(t *testing.T) {
	cond := NamespaceAllowlist{}

	tests := []struct {
		name      string
		req       domain.AccessRequest
		config    domain.PolicyConfig
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "namespace in approved list, no match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "library"},
			},
			config:    &domain.NamespaceListPolicyConfig{Namespaces: []string{"library", "docker"}},
			wantMatch: false,
		},
		{
			name: "namespace outside approved list, match",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "random-org"},
			},
			config:    &domain.NamespaceListPolicyConfig{Namespaces: []string{"library", "docker"}},
			wantMatch: true,
		},
		{
			name: "missing config key, error",
			req: domain.AccessRequest{
				Artifact: domain.ArtifactIdentity{Namespace: "random-org"},
			},
			config:  &domain.NamespaceListPolicyConfig{},
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
				assert.Contains(t, reason, "approved namespace list")
			}
		})
	}
}
