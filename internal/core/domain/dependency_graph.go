package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// DependencyGraphStatus describes the lifecycle of one resolved root graph.
type DependencyGraphStatus string

// A root is enqueued as pending, claimed by a resolver worker as resolving, and ends either complete with a stored
// node/edge graph and hash, or failed with an error message and a fixed retry time.
const (
	DependencyGraphPending   DependencyGraphStatus = "pending"
	DependencyGraphResolving DependencyGraphStatus = "resolving"
	DependencyGraphComplete  DependencyGraphStatus = "complete"
	DependencyGraphFailed    DependencyGraphStatus = "failed"
)

// DependencyScope describes how a requested artifact relates to known npm root graphs.
type DependencyScope string

// Scope is derived from the minimum depth at which an artifact appears in resolved graphs: the root itself and depth-1
// packages are direct, deeper packages are transitive, and absent or conflicting evidence normalizes to unknown.
const (
	DependencyScopeDirect     DependencyScope = "direct"
	DependencyScopeTransitive DependencyScope = "transitive"
	DependencyScopeUnknown    DependencyScope = "unknown"
)

// DependencyType classifies an npm dependency edge.
type DependencyType string

// These mirror the npm dependency kinds parsed out of a resolved package lock, and are the values policy targets match
// against in their dependency_types selector.
const (
	DependencyTypeProd     DependencyType = "prod"
	DependencyTypeDev      DependencyType = "dev"
	DependencyTypePeer     DependencyType = "peer"
	DependencyTypeOptional DependencyType = "optional"
)

// DependencyGraphRoot is the durable identity and lifecycle state for an npm root graph.
type DependencyGraphRoot struct {
	ID          string
	TenantID    string
	UpstreamID  string
	PackageName string
	Version     string
	Status      DependencyGraphStatus
	GraphHash   string
	Error       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ResolvedAt  *time.Time
}

// DependencyGraphNode is one normalized npm package/version in a graph.
type DependencyGraphNode struct {
	ID              string
	RootID          string
	Artifact        ArtifactIdentity
	MinDepth        int
	DependencyTypes []DependencyType
}

// DependencyGraphEdge is one parent-to-child npm dependency relationship.
type DependencyGraphEdge struct {
	ID             string
	RootID         string
	ParentNodeID   string
	ChildNodeID    string
	DependencyType DependencyType
}

// DependencyGraphSnapshot is a resolved graph together with its root metadata.
type DependencyGraphSnapshot struct {
	Root  DependencyGraphRoot
	Nodes []DependencyGraphNode
	Edges []DependencyGraphEdge
}

// DependencyContext summarizes graph evidence for a requested npm artifact.
type DependencyContext struct {
	Scope           DependencyScope  `json:"scope"`
	DependencyTypes []DependencyType `json:"dependency_types,omitempty"`
	GraphIDs        []string         `json:"graph_ids,omitempty"`
	ContextHash     string           `json:"context_hash"`
}

// DependencyGraphResolveRequest is an idempotent async graph-resolution job request.
type DependencyGraphResolveRequest struct {
	TenantID    string           `json:"tenant_id"`
	Upstream    Upstream         `json:"upstream"`
	Root        ArtifactIdentity `json:"root"`
	RequestedAt time.Time        `json:"requested_at"`
}

// DependencyContextSummaryKey scopes a cached context summary.
type DependencyContextSummaryKey struct {
	TenantID       string
	OrganizationID string
	TeamID         string
	UpstreamID     string
	Artifact       ArtifactIdentity
}

// NewUnknownDependencyContext returns the stable unknown graph context.
func NewUnknownDependencyContext() DependencyContext {
	ctx := DependencyContext{Scope: DependencyScopeUnknown}
	ctx.ContextHash = ctx.StableHash()
	return ctx
}

// StableHash returns a deterministic hash for the context.
func (c DependencyContext) StableHash() string {
	types := make([]string, 0, len(c.DependencyTypes))
	for _, depType := range c.DependencyTypes {
		types = append(types, string(depType))
	}
	sort.Strings(types)

	graphIDs := append([]string(nil), c.GraphIDs...)
	sort.Strings(graphIDs)

	parts := []string{string(c.Scope), strings.Join(types, ","), strings.Join(graphIDs, ",")}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// Normalize fills defaults and canonical ordering for a dependency context.
func (c DependencyContext) Normalize() DependencyContext {
	if c.Scope == "" {
		c.Scope = DependencyScopeUnknown
	}
	c.DependencyTypes = uniqueDependencyTypes(c.DependencyTypes)
	c.GraphIDs = uniqueStrings(c.GraphIDs)
	if c.ContextHash == "" {
		c.ContextHash = c.StableHash()
	}
	return c
}

func uniqueDependencyTypes(values []DependencyType) []DependencyType {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[DependencyType]struct{}, len(values))
	result := make([]DependencyType, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})
	return result
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
