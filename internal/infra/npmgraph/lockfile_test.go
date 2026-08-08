package npmgraph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestParsePackageLock(t *testing.T) {
	t.Parallel()

	root := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "@scope/root",
		Version:   "1.0.0",
	}
	lockfile := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "@scope/root",
				"version": "1.0.0",
				"dependencies": {"left-pad": "^1.3.0"},
				"peerDependencies": {"react": "^18.0.0"},
				"optionalDependencies": {"fsevents": "^2.3.0"}
			},
			"node_modules/left-pad": {
				"version": "1.3.0",
				"dependencies": {"ansi": "^1.0.0"}
			},
			"node_modules/left-pad/node_modules/ansi": {
				"name": "ansi",
				"version": "1.0.0"
			},
			"node_modules/react": {
				"version": "18.2.0"
			},
			"node_modules/fsevents": {
				"version": "2.3.3",
				"optional": true
			}
		}
	}`)

	nodes, edges, graphHash, err := ParsePackageLock(root, lockfile)
	require.NoError(t, err)
	require.NotEmpty(t, graphHash)

	byID := map[string]domain.DependencyGraphNode{}
	for _, node := range nodes {
		byID[node.ID] = node
	}

	assert.Equal(t, 5, len(nodes))
	assert.Equal(t, 4, len(edges))
	assert.Equal(t, 0, byID["npm:@scope/root:1.0.0"].MinDepth)
	assert.Equal(t, 1, byID["npm:left-pad:1.3.0"].MinDepth)
	assert.Equal(t, 2, byID["npm:ansi:1.0.0"].MinDepth)
	assert.Contains(t, byID["npm:react:18.2.0"].DependencyTypes, domain.DependencyTypePeer)
	assert.Contains(t, byID["npm:fsevents:2.3.3"].DependencyTypes, domain.DependencyTypeOptional)
}

func TestParsePackageLock_MergesDuplicatePackageVersionNodes(t *testing.T) {
	t.Parallel()

	root := domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "root", Version: "1.0.0"}
	lockfile := []byte(`{
		"packages": {
			"": {"name": "root", "version": "1.0.0", "dependencies": {"a": "1.0.0", "b": "1.0.0"}},
			"node_modules/a": {"version": "1.0.0", "dependencies": {"shared": "1.0.0"}},
			"node_modules/a/node_modules/shared": {"version": "1.0.0"},
			"node_modules/b": {"version": "1.0.0", "dependencies": {"shared": "1.0.0"}},
			"node_modules/b/node_modules/shared": {"version": "1.0.0"}
		}
	}`)

	nodes, edges, _, err := ParsePackageLock(root, lockfile)
	require.NoError(t, err)

	sharedCount := 0
	for _, node := range nodes {
		if node.ID == "npm:shared:1.0.0" {
			sharedCount++
		}
	}
	assert.Equal(t, 1, sharedCount)
	assert.Equal(t, 4, len(nodes))
	assert.Equal(t, 4, len(edges))
}

func TestParsePackageLock_RejectsMalformedLockfile(t *testing.T) {
	t.Parallel()

	root := domain.ArtifactIdentity{Ecosystem: domain.EcosystemNPM, Name: "root", Version: "1.0.0"}
	_, _, _, err := ParsePackageLock(root, []byte(`{"packages":{"node_modules/a":{"version":""}}}`))
	require.Error(t, err)
}
