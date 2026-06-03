package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NormalizeArtifactIdentity_OCI(t *testing.T) {
	tests := []struct {
		name    string
		input   ArtifactIdentity
		want    ArtifactIdentity
		wantErr bool
	}{
		{
			name: "basic image with tag",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "1.25",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "1.25",
			},
		},
		{
			name: "digest reference moves to Digest field",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "sha256:abc123def456",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "",
				Digest:    "sha256:abc123def456",
			},
		},
		{
			name: "sha512 digest reference moves to Digest field",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "sha512:abc123def456",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "",
				Digest:    "sha512:abc123def456",
			},
		},
		{
			name: "missing name returns error",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "",
				Version:   "1.25",
			},
			wantErr: true,
		},
		{
			name: "no version or digest defaults to latest",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "latest",
			},
		},
		{
			name: "namespace trimming strips slashes",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "/library/",
				Name:      "nginx",
				Version:   "1.25",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "library",
				Name:      "nginx",
				Version:   "1.25",
			},
		},
		{
			name: "already normalized is unchanged",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "library",
				Name:      "nginx",
				Version:   "1.25",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "library",
				Name:      "nginx",
				Version:   "1.25",
			},
		},
		{
			name: "uppercase name is lowercased",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "Docker.IO/Library",
				Name:      "NGINX",
				Version:   "1.25",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "docker.io/library",
				Name:      "nginx",
				Version:   "1.25",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeArtifactIdentity(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidArtifactRef)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_NormalizeArtifactIdentity_NPM(t *testing.T) {
	tests := []struct {
		name    string
		input   ArtifactIdentity
		want    ArtifactIdentity
		wantErr bool
	}{
		{
			name: "scoped package splits namespace and name",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "@types/node",
				Version:   "20.0.0",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Namespace: "@types",
				Name:      "node",
				Version:   "20.0.0",
			},
		},
		{
			name: "unscoped package lowercased",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "Express",
				Version:   "4.18.0",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
				Version:   "4.18.0",
			},
		},
		{
			name: "invalid scope missing name after slash",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "@types/",
			},
			wantErr: true,
		},
		{
			name: "scope without slash",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "@types",
			},
			wantErr: true,
		},
		{
			name: "empty name returns error",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "",
			},
			wantErr: true,
		},
		{
			name: "scoped package with uppercase",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "@MyOrg/MyPkg",
				Version:   "1.0.0",
			},
			want: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Namespace: "@myorg",
				Name:      "mypkg",
				Version:   "1.0.0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeArtifactIdentity(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidArtifactRef)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_NormalizeArtifactIdentity_unsupported_ecosystem(t *testing.T) {
	_, err := NormalizeArtifactIdentity(ArtifactIdentity{
		Ecosystem: "pypi",
		Name:      "requests",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArtifactRef)
}

func Test_ArtifactIdentity_CacheKey(t *testing.T) {
	tests := []struct {
		name  string
		input ArtifactIdentity
		want  string
	}{
		{
			name: "OCI with digest",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "library",
				Name:      "nginx",
				Digest:    "sha256:abc",
			},
			want: "oci:library/nginx@sha256:abc",
		},
		{
			name: "OCI with tag",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "library",
				Name:      "nginx",
				Version:   "latest",
			},
			want: "oci:library/nginx:latest",
		},
		{
			name: "NPM with scope",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Namespace: "@types",
				Name:      "node",
				Version:   "1.0.0",
			},
			want: "npm:@types/node:1.0.0",
		},
		{
			name: "NPM without scope",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
				Version:   "4.18.0",
			},
			want: "npm:express:4.18.0",
		},
		{
			name: "no version or digest",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
			},
			want: "npm:express",
		},
		{
			name: "digest takes precedence over version in key",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Namespace: "library",
				Name:      "nginx",
				Version:   "1.25",
				Digest:    "sha256:abc",
			},
			want: "oci:library/nginx@sha256:abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.input.CacheKey())
		})
	}
}

func Test_ArtifactIdentity_IsMutableReference(t *testing.T) {
	tests := []struct {
		name  string
		input ArtifactIdentity
		want  bool
	}{
		{
			name: "has digest is immutable",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Name:      "nginx",
				Digest:    "sha256:abc",
			},
			want: false,
		},
		{
			name: "has version no digest is mutable",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Name:      "nginx",
				Version:   "latest",
			},
			want: true,
		},
		{
			name: "neither version nor digest is not mutable",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
			},
			want: false,
		},
		{
			name: "both version and digest is immutable",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Name:      "nginx",
				Version:   "1.25",
				Digest:    "sha256:abc",
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.input.IsMutableReference())
		})
	}
}

func Test_ArtifactIdentity_IsNPMDistTag(t *testing.T) {
	tests := []struct {
		name  string
		input ArtifactIdentity
		want  bool
	}{
		{
			name: "npm latest tag",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
				Version:   "latest",
			},
			want: true,
		},
		{
			name: "npm next tag",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
				Version:   "next",
			},
			want: true,
		},
		{
			name: "npm concrete semver",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
				Version:   "4.18.2",
			},
			want: false,
		},
		{
			name: "npm prerelease semver",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
				Version:   "5.0.0-beta.1",
			},
			want: false,
		},
		{
			name: "npm bare package",
			input: ArtifactIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "express",
			},
			want: false,
		},
		{
			name: "oci tag is not npm dist-tag",
			input: ArtifactIdentity{
				Ecosystem: EcosystemOCI,
				Name:      "nginx",
				Version:   "latest",
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.input.IsNPMDistTag())
		})
	}
}
