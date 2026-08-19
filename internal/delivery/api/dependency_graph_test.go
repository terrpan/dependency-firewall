package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestToDependencyGraphResponse(t *testing.T) {
	resolvedAt := time.Date(2026, time.August, 7, 10, 11, 12, 0, time.UTC)
	snapshot := &domain.DependencyGraphSnapshot{
		Root: domain.DependencyGraphRoot{
			ID:          "root-1",
			TenantID:    "tenant-1",
			UpstreamID:  "upstream-1",
			PackageName: "@acme/app",
			Version:     "1.2.3",
			Status:      domain.DependencyGraphComplete,
			GraphHash:   "hash-1",
			CreatedAt:   resolvedAt.Add(-time.Minute),
			UpdatedAt:   resolvedAt,
			ResolvedAt:  &resolvedAt,
		},
		Nodes: []domain.DependencyGraphNode{
			{
				ID:     "node-root",
				RootID: "root-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Namespace: "acme",
					Name:      "app",
					Version:   "1.2.3",
				},
				MinDepth:        0,
				DependencyTypes: []domain.DependencyType{domain.DependencyTypeProd},
			},
			{
				ID:     "node-child",
				RootID: "root-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "kleur",
					Version:   "4.1.5",
				},
				MinDepth:        1,
				DependencyTypes: []domain.DependencyType{domain.DependencyTypeOptional},
			},
		},
		Edges: []domain.DependencyGraphEdge{
			{
				ID:             "edge-1",
				RootID:         "root-1",
				ParentNodeID:   "node-root",
				ChildNodeID:    "node-child",
				DependencyType: domain.DependencyTypeOptional,
			},
		},
	}

	response := toDependencyGraphResponse(snapshot)

	assert.Equal(t, "root-1", response.Root.ID)
	assert.Equal(t, "complete", response.Root.Status)
	assert.Equal(t, "2026-08-07T10:11:12Z", *response.Root.ResolvedAt)
	assert.Equal(t, "npm", response.Nodes[0].Artifact.Ecosystem)
	assert.Equal(t, []string{"optional"}, response.Nodes[1].DependencyTypes)
	assert.Equal(t, "node-root", response.Edges[0].ParentNodeID)
	assert.Equal(t, "optional", response.Edges[0].DependencyType)
}

func TestToDependencyGraphRootResponseOmitsUnresolvedTimestamp(t *testing.T) {
	response := toDependencyGraphRootResponse(
		domain.DependencyGraphRoot{ID: "root-1", Status: domain.DependencyGraphPending},
	)

	assert.Nil(t, response.ResolvedAt)
	assert.Equal(t, "pending", response.Status)
}
