package domain

import (
	"strings"
	"time"
)

// ArtifactIdentity is the canonical, normalized identifier for a package or image.
type ArtifactIdentity struct {
	Ecosystem EcosystemType
	Namespace string // e.g., npm scope or OCI registry/org
	Name      string
	Version   string // semver for npm, tag or digest for OCI
	Digest    string // immutable content hash (sha256:...), populated when resolved
}

// AccessRequestKind identifies the protocol-level request shape.
type AccessRequestKind string

// The npm proxy distinguishes packument (metadata) requests from tarball downloads because only a tarball request
// carries a concrete version, and version-sensitive enrichment and decision caching depend on that distinction.
const (
	AccessRequestKindNPMMetadata AccessRequestKind = "npm_metadata"
	AccessRequestKindNPMTarball  AccessRequestKind = "npm_tarball"
)

// AccessRequest is the normalized input to the policy engine.
type AccessRequest struct {
	TenantID          string
	RequestID         string
	Kind              AccessRequestKind
	Artifact          ArtifactIdentity
	Upstream          Upstream
	Metadata          *ArtifactMetadata
	DependencyContext *DependencyContext
	Timestamp         time.Time
}

// ArtifactMetadata holds enrichment data about an artifact.
type ArtifactMetadata struct {
	PublishedAt      *time.Time
	MaxCVSS          *float64
	Licenses         []string
	Vulnerabilities  []Vulnerability
	IsMutableTag     bool
	SourceRepository *SourceRepository
	Scorecard        *ScorecardResult
}

// SourceRepository identifies the source repository associated with an artifact.
type SourceRepository struct {
	Host  string
	Owner string
	Repo  string
}

// ProjectURI returns the Scorecard-compatible repository identifier.
func (r SourceRepository) ProjectURI() string {
	host := strings.TrimSpace(strings.ToLower(r.Host))
	owner := strings.TrimSpace(r.Owner)
	repo := strings.TrimSpace(r.Repo)
	if host == "" || owner == "" || repo == "" {
		return ""
	}
	return host + "/" + owner + "/" + repo
}

// DisplayName returns a human-friendly repository identifier.
func (r SourceRepository) DisplayName() string {
	owner := strings.TrimSpace(r.Owner)
	repo := strings.TrimSpace(r.Repo)
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}

// ScorecardResult holds hosted Scorecard data for a source repository.
type ScorecardResult struct {
	Score             *float64
	Checks            map[string]float64
	UnavailableReason string
}

// Vulnerability holds data from enrichment sources like OSV.
type Vulnerability struct {
	ID       string
	Severity string
	CVSS     float64
	Summary  string
}
