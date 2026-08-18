package npmgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type packageLock struct {
	Packages map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
}

// ParsePackageLock converts an npm package-lock.json into graph nodes and edges.
func ParsePackageLock(
	root domain.ArtifactIdentity,
	data []byte,
) ([]domain.DependencyGraphNode, []domain.DependencyGraphEdge, string, error) {
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil, "", fmt.Errorf("parsing package-lock.json: %w", err)
	}
	if len(lock.Packages) == 0 {
		return nil, nil, "", fmt.Errorf("parsing package-lock.json: packages is required")
	}

	root = rootWithFullName(root)
	paths := sortedPackagePaths(lock.Packages)
	pathNodeIDs := make(map[string]string, len(paths))
	nodesByKey := make(map[string]*domain.DependencyGraphNode, len(paths))

	for _, lockPath := range paths {
		artifact, err := artifactForLockPackage(root, lockPath, lock.Packages[lockPath])
		if err != nil {
			return nil, nil, "", err
		}
		key := artifact.CacheKey()
		node, ok := nodesByKey[key]
		if !ok {
			node = &domain.DependencyGraphNode{
				ID:       key,
				Artifact: artifact,
				MinDepth: -1,
			}
			nodesByKey[key] = node
		}
		pathNodeIDs[lockPath] = node.ID
	}

	edgeKeys := map[string]struct{}{}
	var edges []domain.DependencyGraphEdge
	for _, lockPath := range paths {
		parentID := pathNodeIDs[lockPath]
		pkg := lock.Packages[lockPath]
		for depName, depType := range dependencyEntries(pkg) {
			childPath, ok := resolveDependencyPath(lock.Packages, lockPath, depName)
			if !ok {
				continue
			}
			childID := pathNodeIDs[childPath]
			key := parentID + ">" + childID + ":" + string(depType)
			if _, exists := edgeKeys[key]; exists {
				continue
			}
			edgeKeys[key] = struct{}{}
			edges = append(edges, domain.DependencyGraphEdge{
				ParentNodeID:   parentID,
				ChildNodeID:    childID,
				DependencyType: depType,
			})
			if child := nodesByKey[childID]; child != nil {
				child.DependencyTypes = append(child.DependencyTypes, depType)
			}
		}
	}

	nodes := make([]domain.DependencyGraphNode, 0, len(nodesByKey))
	for _, node := range nodesByKey {
		node.DependencyTypes = uniqueDependencyTypes(node.DependencyTypes)
		nodes = append(nodes, *node)
	}
	computeDepths(root.CacheKey(), nodes, edges)
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ParentNodeID != edges[j].ParentNodeID {
			return edges[i].ParentNodeID < edges[j].ParentNodeID
		}
		if edges[i].ChildNodeID != edges[j].ChildNodeID {
			return edges[i].ChildNodeID < edges[j].ChildNodeID
		}
		return edges[i].DependencyType < edges[j].DependencyType
	})

	hash := graphHash(nodes, edges)
	return nodes, edges, hash, nil
}

func rootWithFullName(root domain.ArtifactIdentity) domain.ArtifactIdentity {
	root.Ecosystem = domain.EcosystemNPM
	if root.Namespace != "" {
		root.Name = root.Namespace + "/" + root.Name
		root.Namespace = ""
	}
	normalized, err := domain.NormalizeArtifactIdentity(root)
	if err != nil {
		return root
	}
	return normalized
}

func sortedPackagePaths(packages map[string]lockPackage) []string {
	paths := make([]string, 0, len(packages))
	for lockPath := range packages {
		paths = append(paths, lockPath)
	}
	sort.Strings(paths)
	return paths
}

func artifactForLockPackage(
	root domain.ArtifactIdentity,
	lockPath string,
	pkg lockPackage,
) (domain.ArtifactIdentity, error) {
	if lockPath == "" {
		if root.Version == "" {
			return domain.ArtifactIdentity{}, fmt.Errorf("parsing package-lock.json: root version is required")
		}
		return root, nil
	}
	name := pkg.Name
	if name == "" {
		name = packageNameFromLockPath(lockPath)
	}
	if name == "" || pkg.Version == "" {
		return domain.ArtifactIdentity{}, fmt.Errorf(
			"parsing package-lock.json: package %q has missing name or version",
			lockPath,
		)
	}
	artifact, err := domain.NormalizeArtifactIdentity(domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      name,
		Version:   pkg.Version,
	})
	if err != nil {
		return domain.ArtifactIdentity{}, fmt.Errorf("normalizing lock package %q: %w", lockPath, err)
	}
	return artifact, nil
}

func packageNameFromLockPath(lockPath string) string {
	lockPath = strings.TrimPrefix(lockPath, "node_modules/")
	parts := strings.Split(lockPath, "/node_modules/")
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	if strings.HasPrefix(last, "@") {
		scopeParts := strings.SplitN(last, "/", 3)
		if len(scopeParts) >= 2 {
			return scopeParts[0] + "/" + scopeParts[1]
		}
	}
	return strings.SplitN(last, "/", 2)[0]
}

func dependencyEntries(pkg lockPackage) map[string]domain.DependencyType {
	entries := make(map[string]domain.DependencyType)
	for name := range pkg.Dependencies {
		entries[name] = domain.DependencyTypeProd
	}
	for name := range pkg.DevDependencies {
		entries[name] = domain.DependencyTypeDev
	}
	for name := range pkg.PeerDependencies {
		entries[name] = domain.DependencyTypePeer
	}
	for name := range pkg.OptionalDependencies {
		entries[name] = domain.DependencyTypeOptional
	}
	return entries
}

func resolveDependencyPath(packages map[string]lockPackage, parentPath, depName string) (string, bool) {
	for dir := parentPath; ; dir = path.Dir(dir) {
		candidate := path.Join(dir, "node_modules", depName)
		if _, ok := packages[candidate]; ok {
			return candidate, true
		}
		if dir == "." || dir == "/" || dir == "" {
			break
		}
	}
	candidate := path.Join("node_modules", depName)
	_, ok := packages[candidate]
	return candidate, ok
}

func computeDepths(rootID string, nodes []domain.DependencyGraphNode, edges []domain.DependencyGraphEdge) {
	byID := make(map[string]*domain.DependencyGraphNode, len(nodes))
	for i := range nodes {
		byID[nodes[i].ID] = &nodes[i]
	}
	if root := byID[rootID]; root != nil {
		root.MinDepth = 0
	}
	adjacency := make(map[string][]string)
	for _, edge := range edges {
		adjacency[edge.ParentNodeID] = append(adjacency[edge.ParentNodeID], edge.ChildNodeID)
	}
	queue := []string{rootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		currentNode := byID[current]
		if currentNode == nil || currentNode.MinDepth < 0 {
			continue
		}
		for _, child := range adjacency[current] {
			childNode := byID[child]
			if childNode == nil {
				continue
			}
			depth := currentNode.MinDepth + 1
			if childNode.MinDepth == -1 || depth < childNode.MinDepth {
				childNode.MinDepth = depth
				queue = append(queue, child)
			}
		}
	}
	for i := range nodes {
		if node := byID[nodes[i].ID]; node != nil {
			nodes[i].MinDepth = node.MinDepth
			nodes[i].DependencyTypes = node.DependencyTypes
		}
	}
}

func uniqueDependencyTypes(values []domain.DependencyType) []domain.DependencyType {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[domain.DependencyType]struct{}, len(values))
	result := make([]domain.DependencyType, 0, len(values))
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

func graphHash(nodes []domain.DependencyGraphNode, edges []domain.DependencyGraphEdge) string {
	type hashNode struct {
		ID    string                  `json:"id"`
		Depth int                     `json:"depth"`
		Types []domain.DependencyType `json:"types"`
	}
	type hashEdge struct {
		Parent string                `json:"parent"`
		Child  string                `json:"child"`
		Type   domain.DependencyType `json:"type"`
	}
	payload := struct {
		Nodes []hashNode `json:"nodes"`
		Edges []hashEdge `json:"edges"`
	}{}
	for _, node := range nodes {
		payload.Nodes = append(payload.Nodes, hashNode{
			ID:    node.ID,
			Depth: node.MinDepth,
			Types: node.DependencyTypes,
		})
	}
	for _, edge := range edges {
		payload.Edges = append(payload.Edges, hashEdge{
			Parent: edge.ParentNodeID,
			Child:  edge.ChildNodeID,
			Type:   edge.DependencyType,
		})
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
