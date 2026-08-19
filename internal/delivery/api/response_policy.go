package api

import (
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// PolicyResponse is the wire form of a tenant policy at its current version. UpstreamID is empty for a legacy
// tenant-wide policy, Target is present only when the policy is restricted by dependency graph context, and Config is
// the typed configuration for the policy type at the declared schema version.
type PolicyResponse struct {
	ID            string               `json:"id"`
	UpstreamID    string               `json:"upstream_id,omitempty"`
	Name          string               `json:"name"`
	Type          string               `json:"type"`
	Action        string               `json:"action"`
	SchemaVersion int                  `json:"schema_version"`
	Target        *domain.PolicyTarget `json:"target,omitempty"`
	Config        any                  `json:"config"`
	Priority      int                  `json:"priority"`
	Enabled       bool                 `json:"enabled"`
	Version       int                  `json:"version"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
}

// PolicyVersionResponse is the wire form of one retained policy snapshot. It carries the full state that a rollback
// would restore, so the UI can diff historical versions; only the most recent snapshots per policy are kept.
type PolicyVersionResponse struct {
	Version       int                  `json:"version"`
	UpstreamID    string               `json:"upstream_id,omitempty"`
	Name          string               `json:"name"`
	Type          string               `json:"type"`
	Action        string               `json:"action"`
	SchemaVersion int                  `json:"schema_version"`
	Target        *domain.PolicyTarget `json:"target,omitempty"`
	Config        any                  `json:"config"`
	Priority      int                  `json:"priority"`
	Enabled       bool                 `json:"enabled"`
	CreatedAt     time.Time            `json:"created_at"`
}

// PolicyTypeResponse is the wire form of one entry in the compiled policy-type catalog. It tells clients which schema
// versions and actions a type accepts, which ecosystems it applies to, and which upstream enrichment capabilities an
// upstream must provide before a policy of this type can be scoped to it.
type PolicyTypeResponse struct {
	Type                    string   `json:"type"`
	Summary                 string   `json:"summary"`
	Description             string   `json:"description"`
	Help                    string   `json:"help"`
	CurrentSchemaVersion    int      `json:"current_schema_version"`
	SupportedSchemaVersions []int    `json:"supported_schema_versions"`
	SupportedActions        []string `json:"supported_actions"`
	SupportedEcosystems     []string `json:"supported_ecosystems"`
	RequiredCapabilities    []string `json:"required_capabilities"`
	Example                 string   `json:"example"`
}

func toPolicyResponse(p *domain.Policy) *PolicyResponse {
	return &PolicyResponse{
		ID:            p.ID,
		UpstreamID:    p.UpstreamID,
		Name:          p.Name,
		Type:          string(p.Type),
		Action:        string(p.Action),
		SchemaVersion: p.SchemaVersion,
		Target:        p.Target,
		Config:        p.Config,
		Priority:      p.Priority,
		Enabled:       p.Enabled,
		Version:       p.Version,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
	}
}

func toPoliciesResponse(policies []domain.Policy) []*PolicyResponse {
	result := make([]*PolicyResponse, len(policies))
	for i := range policies {
		result[i] = toPolicyResponse(&policies[i])
	}
	return result
}

func toPolicyVersionResponse(version *domain.PolicyVersion) *PolicyVersionResponse {
	return &PolicyVersionResponse{
		Version:       version.Version,
		UpstreamID:    version.UpstreamID,
		Name:          version.Name,
		Type:          string(version.Type),
		Action:        string(version.Action),
		SchemaVersion: version.SchemaVersion,
		Target:        version.Target,
		Config:        version.Config,
		Priority:      version.Priority,
		Enabled:       version.Enabled,
		CreatedAt:     version.CreatedAt,
	}
}

func toPolicyVersionsResponse(versions []domain.PolicyVersion) []*PolicyVersionResponse {
	result := make([]*PolicyVersionResponse, len(versions))
	for i := range versions {
		result[i] = toPolicyVersionResponse(&versions[i])
	}
	return result
}

func toPolicyTypeResponse(d domain.PolicyTypeDescriptor) *PolicyTypeResponse {
	actions := make([]string, len(d.SupportedActions))
	for i := range d.SupportedActions {
		actions[i] = string(d.SupportedActions[i])
	}
	ecosystems := make([]string, len(d.SupportedEcosystems))
	for i := range d.SupportedEcosystems {
		ecosystems[i] = string(d.SupportedEcosystems[i])
	}

	return &PolicyTypeResponse{
		Type:                    string(d.Type),
		Summary:                 d.Summary,
		Description:             d.Description,
		Help:                    d.Help,
		CurrentSchemaVersion:    d.CurrentSchemaVersion,
		SupportedSchemaVersions: append([]int(nil), d.SupportedSchemaVersions...),
		SupportedActions:        actions,
		SupportedEcosystems:     ecosystems,
		RequiredCapabilities:    domain.UpstreamCapabilityStrings(d.RequiredCapabilities),
		Example:                 d.Example,
	}
}

func toPolicyTypesResponse(descriptors []domain.PolicyTypeDescriptor) []*PolicyTypeResponse {
	result := make([]*PolicyTypeResponse, len(descriptors))
	for i := range descriptors {
		result[i] = toPolicyTypeResponse(descriptors[i])
	}
	return result
}
