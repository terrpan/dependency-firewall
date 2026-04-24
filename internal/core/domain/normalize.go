package domain

import (
	"fmt"
	"strings"
)

// NormalizeArtifactIdentity canonicalizes an artifact identity.
func NormalizeArtifactIdentity(artifact ArtifactIdentity) (ArtifactIdentity, error) {
	switch artifact.Ecosystem {
	case EcosystemOCI:
		return normalizeOCI(artifact)
	case EcosystemNPM:
		return normalizeNPM(artifact)
	default:
		return artifact, fmt.Errorf("%w: unsupported ecosystem %q", ErrInvalidArtifactRef, artifact.Ecosystem)
	}
}

func normalizeOCI(a ArtifactIdentity) (ArtifactIdentity, error) {
	a.Namespace = strings.ToLower(strings.Trim(a.Namespace, "/"))
	a.Name = strings.ToLower(a.Name)

	if a.Name == "" {
		return a, fmt.Errorf("%w: OCI artifact name is required", ErrInvalidArtifactRef)
	}

	// If version looks like a digest, move it to Digest.
	if strings.HasPrefix(a.Version, "sha256:") || strings.HasPrefix(a.Version, "sha512:") {
		a.Digest = a.Version
		a.Version = ""
	}

	if a.Version == "" && a.Digest == "" {
		a.Version = "latest"
	}

	return a, nil
}

func normalizeNPM(a ArtifactIdentity) (ArtifactIdentity, error) {
	// Handle scoped packages: @scope/name
	if strings.HasPrefix(a.Name, "@") {
		parts := strings.SplitN(a.Name, "/", 2)
		if len(parts) != 2 || parts[1] == "" {
			return a, fmt.Errorf("%w: invalid scoped npm package %q", ErrInvalidArtifactRef, a.Name)
		}
		a.Namespace = strings.ToLower(parts[0])
		a.Name = strings.ToLower(parts[1])
	} else {
		a.Name = strings.ToLower(a.Name)
	}

	if a.Name == "" {
		return a, fmt.Errorf("%w: npm package name is required", ErrInvalidArtifactRef)
	}

	return a, nil
}

// FullName returns the canonical package name including namespace if present.
// For npm: "@scope/name" or "name". For OCI: "namespace/name" or "name".
func (a ArtifactIdentity) FullName() string {
	if a.Namespace != "" {
		return a.Namespace + "/" + a.Name
	}
	return a.Name
}

// CacheKey returns a stable string key for use in caching.
func (a ArtifactIdentity) CacheKey() string {
	var b strings.Builder
	b.WriteString(string(a.Ecosystem))
	b.WriteByte(':')
	if a.Namespace != "" {
		b.WriteString(a.Namespace)
		b.WriteByte('/')
	}
	b.WriteString(a.Name)
	if a.Digest != "" {
		b.WriteByte('@')
		b.WriteString(a.Digest)
	} else if a.Version != "" {
		b.WriteByte(':')
		b.WriteString(a.Version)
	}
	return b.String()
}

// IsMutableReference returns true if the artifact reference can change over time (e.g., tags).
func (a ArtifactIdentity) IsMutableReference() bool {
	return a.Digest == "" && a.Version != ""
}
