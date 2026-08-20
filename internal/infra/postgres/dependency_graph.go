package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DependencyGraphRepository implements graph persistence using PostgreSQL.
type DependencyGraphRepository struct {
	pool *pgxpool.Pool
}

// ListRoots returns the most recently updated graph roots for a tenant.
func (r *DependencyGraphRepository) ListRoots(
	ctx context.Context,
	tenantID string,
	limit int,
) ([]domain.DependencyGraphRoot, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, upstream_id, package_name, version, status, COALESCE(graph_hash, ''),
		        COALESCE(error, ''), created_at, updated_at, resolved_at
		 FROM dependency_graph_roots
		 WHERE tenant_id = $1
		 ORDER BY updated_at DESC
		 LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing dependency graph roots: %w", err)
	}
	defer rows.Close()

	var roots []domain.DependencyGraphRoot
	for rows.Next() {
		var root domain.DependencyGraphRoot
		if err := rows.Scan(
			&root.ID,
			&root.TenantID,
			&root.UpstreamID,
			&root.PackageName,
			&root.Version,
			&root.Status,
			&root.GraphHash,
			&root.Error,
			&root.CreatedAt,
			&root.UpdatedAt,
			&root.ResolvedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning dependency graph root: %w", err)
		}
		roots = append(roots, root)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating dependency graph roots: %w", err)
	}
	return roots, nil
}

// GetSnapshot returns one tenant-owned graph root and its resolved nodes and edges.
func (r *DependencyGraphRepository) GetSnapshot(
	ctx context.Context,
	tenantID, rootID string,
) (*domain.DependencyGraphSnapshot, error) {
	var snapshot domain.DependencyGraphSnapshot
	if err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, upstream_id, package_name, version, status, COALESCE(graph_hash, ''),
		        COALESCE(error, ''), created_at, updated_at, resolved_at
		 FROM dependency_graph_roots
		 WHERE tenant_id = $1 AND id = $2`, tenantID, rootID,
	).Scan(&snapshot.Root.ID, &snapshot.Root.TenantID, &snapshot.Root.UpstreamID, &snapshot.Root.PackageName,
		&snapshot.Root.Version, &snapshot.Root.Status, &snapshot.Root.GraphHash, &snapshot.Root.Error,
		&snapshot.Root.CreatedAt, &snapshot.Root.UpdatedAt, &snapshot.Root.ResolvedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrArtifactNotFound
		}
		return nil, fmt.Errorf("loading dependency graph root: %w", err)
	}

	nodeRows, err := r.pool.Query(ctx,
		`SELECT id, root_id, ecosystem, namespace, name, version, digest, min_depth, dependency_types
		 FROM dependency_graph_nodes
		 WHERE root_id = $1
		 ORDER BY min_depth, name, version`, rootID)
	if err != nil {
		return nil, fmt.Errorf("loading dependency graph nodes: %w", err)
	}
	defer nodeRows.Close()
	for nodeRows.Next() {
		var node domain.DependencyGraphNode
		var ecosystem string
		var dependencyTypes []string
		if err := nodeRows.Scan(&node.ID, &node.RootID, &ecosystem, &node.Artifact.Namespace, &node.Artifact.Name,
			&node.Artifact.Version, &node.Artifact.Digest, &node.MinDepth, &dependencyTypes); err != nil {
			return nil, fmt.Errorf("scanning dependency graph node: %w", err)
		}
		node.Artifact.Ecosystem = domain.EcosystemType(ecosystem)
		for _, dependencyType := range dependencyTypes {
			node.DependencyTypes = append(node.DependencyTypes, domain.DependencyType(dependencyType))
		}
		snapshot.Nodes = append(snapshot.Nodes, node)
	}
	if err := nodeRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating dependency graph nodes: %w", err)
	}

	edgeRows, err := r.pool.Query(ctx,
		`SELECT id, root_id, parent_node_id, child_node_id, dependency_type
		 FROM dependency_graph_edges
		 WHERE root_id = $1
		 ORDER BY parent_node_id, child_node_id, dependency_type`, rootID)
	if err != nil {
		return nil, fmt.Errorf("loading dependency graph edges: %w", err)
	}
	defer edgeRows.Close()
	for edgeRows.Next() {
		var edge domain.DependencyGraphEdge
		var dependencyType string
		if err := edgeRows.Scan(
			&edge.ID,
			&edge.RootID,
			&edge.ParentNodeID,
			&edge.ChildNodeID,
			&dependencyType,
		); err != nil {
			return nil, fmt.Errorf("scanning dependency graph edge: %w", err)
		}
		edge.DependencyType = domain.DependencyType(dependencyType)
		snapshot.Edges = append(snapshot.Edges, edge)
	}
	if err := edgeRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating dependency graph edges: %w", err)
	}

	return &snapshot, nil
}

// NewDependencyGraphRepository creates a new DependencyGraphRepository.
func NewDependencyGraphRepository(pool *pgxpool.Pool) *DependencyGraphRepository {
	return &DependencyGraphRepository{pool: pool}
}

// EnqueueResolve inserts one idempotent async graph resolve request.
func (r *DependencyGraphRepository) EnqueueResolve(
	ctx context.Context,
	req domain.DependencyGraphResolveRequest,
) (bool, error) {
	rootPackage := req.Root.FullName()
	if rootPackage == "" || req.Root.Version == "" {
		return false, fmt.Errorf("enqueueing dependency graph resolve: root package and version are required")
	}
	tag, err := r.pool.Exec(ctx,
		`INSERT INTO dependency_graph_roots (tenant_id, upstream_id, package_name, version, status, updated_at)
		 VALUES ($1, $2, $3, $4, $5, now())
		 ON CONFLICT ON CONSTRAINT dependency_graph_roots_scope_identity_key DO NOTHING`,
		req.TenantID, req.Upstream.ID, rootPackage, req.Root.Version, domain.DependencyGraphPending,
	)
	if err != nil {
		return false, fmt.Errorf("enqueueing dependency graph resolve: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ClaimNextResolveJob claims one pending or retryable failed job.
func (r *DependencyGraphRepository) ClaimNextResolveJob(
	ctx context.Context,
	tenantID string,
	now time.Time,
) (*domain.DependencyGraphResolveRequest, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("claiming dependency graph resolve: tenant_id is required")
	}
	var tenantFilter any
	if tenantID != "*" {
		tenantFilter = tenantID
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning dependency graph claim: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once the tx has committed; nothing to report on the happy path

	var claimedTenantID, upstreamID, packageName, version, baseURL string
	err = tx.QueryRow(ctx,
		`WITH next_job AS (
		     SELECT id
		     FROM dependency_graph_roots
		     WHERE status IN ('pending', 'failed')
		       AND updated_at <= $1
		       AND ($2::uuid IS NULL OR tenant_id = $2::uuid)
		     ORDER BY updated_at ASC
		     LIMIT 1
		     FOR UPDATE SKIP LOCKED
		 )
		 UPDATE dependency_graph_roots dgr
		 SET status = 'resolving', updated_at = now(), error = NULL
		 FROM next_job, upstreams u
		 WHERE dgr.id = next_job.id
		   AND u.id = dgr.upstream_id
		 RETURNING dgr.tenant_id, dgr.upstream_id, dgr.package_name, dgr.version, u.base_url`,
		now, tenantFilter,
	).Scan(&claimedTenantID, &upstreamID, &packageName, &version, &baseURL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("claiming dependency graph resolve: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing dependency graph claim: %w", err)
	}

	root, err := domain.NormalizeArtifactIdentity(domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      packageName,
		Version:   version,
	})
	if err != nil {
		return nil, fmt.Errorf("normalizing claimed root artifact: %w", err)
	}
	return &domain.DependencyGraphResolveRequest{
		TenantID: claimedTenantID,
		Upstream: domain.Upstream{
			ID:        upstreamID,
			TenantID:  claimedTenantID,
			Ecosystem: domain.EcosystemNPM,
			BaseURL:   baseURL,
		},
		Root:        root,
		RequestedAt: now,
	}, nil
}

// CompleteResolve transactionally replaces the graph and context summaries for one root.
func (r *DependencyGraphRepository) CompleteResolve(
	ctx context.Context,
	req domain.DependencyGraphResolveRequest,
	nodes []domain.DependencyGraphNode,
	edges []domain.DependencyGraphEdge,
	graphHash string,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning dependency graph completion: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once the tx has committed; nothing to report on the happy path

	rootID, err := dependencyGraphRootID(ctx, tx, req)
	if err != nil {
		return err
	}
	if err := clearDependencyGraph(ctx, tx, rootID); err != nil {
		return err
	}
	nodeIDs, err := insertDependencyGraphNodes(ctx, tx, req, rootID, nodes)
	if err != nil {
		return err
	}
	if err := insertDependencyGraphEdges(ctx, tx, req, rootID, nodeIDs, edges); err != nil {
		return err
	}
	if err := markDependencyGraphComplete(ctx, tx, rootID, graphHash); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing dependency graph completion: %w", err)
	}
	return nil
}

func clearDependencyGraph(ctx context.Context, tx pgx.Tx, rootID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM dependency_context_summaries WHERE root_id = $1`, rootID); err != nil {
		return fmt.Errorf("clearing dependency context summaries: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM dependency_graph_nodes WHERE root_id = $1`, rootID); err != nil {
		return fmt.Errorf("clearing dependency graph nodes: %w", err)
	}
	return nil
}

func insertDependencyGraphNodes(
	ctx context.Context,
	tx pgx.Tx,
	req domain.DependencyGraphResolveRequest,
	rootID string,
	nodes []domain.DependencyGraphNode,
) (map[string]string, error) {
	nodeIDs := make(map[string]string, len(nodes))
	for i := range nodes {
		node := nodes[i]
		node.RootID = rootID
		depTypes := dependencyTypeStrings(node.DependencyTypes)
		var nodeID string
		err := tx.QueryRow(
			ctx,
			`INSERT INTO dependency_graph_nodes (tenant_id, upstream_id, root_id, ecosystem, namespace, name, version, digest, min_depth, dependency_types)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			 RETURNING id`,
			req.TenantID,
			req.Upstream.ID,
			rootID,
			node.Artifact.Ecosystem,
			node.Artifact.Namespace,
			node.Artifact.Name,
			node.Artifact.Version,
			node.Artifact.Digest,
			node.MinDepth,
			depTypes,
		).Scan(&nodeID)
		if err != nil {
			return nil, fmt.Errorf("inserting dependency graph node: %w", err)
		}
		key := node.ID
		if key == "" {
			key = node.Artifact.CacheKey()
		}
		nodeIDs[key] = nodeID

		dependencyContext := dependencyContextForNode(rootID, node).Normalize()
		if err := insertDependencyContextSummary(ctx, tx, req, rootID, node.Artifact, dependencyContext); err != nil {
			return nil, err
		}
	}
	return nodeIDs, nil
}

func insertDependencyGraphEdges(
	ctx context.Context,
	tx pgx.Tx,
	req domain.DependencyGraphResolveRequest,
	rootID string,
	nodeIDs map[string]string,
	edges []domain.DependencyGraphEdge,
) error {
	for i := range edges {
		edge := edges[i]
		parentID, ok := nodeIDs[edge.ParentNodeID]
		if !ok {
			return fmt.Errorf("inserting dependency graph edge: parent node %q not found", edge.ParentNodeID)
		}
		childID, ok := nodeIDs[edge.ChildNodeID]
		if !ok {
			return fmt.Errorf("inserting dependency graph edge: child node %q not found", edge.ChildNodeID)
		}
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO dependency_graph_edges (tenant_id, upstream_id, root_id, parent_node_id, child_node_id, dependency_type)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (root_id, parent_node_id, child_node_id, dependency_type) DO NOTHING`,
			req.TenantID,
			req.Upstream.ID,
			rootID,
			parentID,
			childID,
			edge.DependencyType,
		); err != nil {
			return fmt.Errorf("inserting dependency graph edge: %w", err)
		}
	}
	return nil
}

func markDependencyGraphComplete(ctx context.Context, tx pgx.Tx, rootID, graphHash string) error {
	if _, err := tx.Exec(ctx,
		`UPDATE dependency_graph_roots
		 SET status = 'complete', graph_hash = $1, error = NULL, updated_at = now(), resolved_at = now()
		 WHERE id = $2`,
		graphHash, rootID,
	); err != nil {
		return fmt.Errorf("marking dependency graph complete: %w", err)
	}
	return nil
}

// FailResolve records a resolver failure and retry window.
func (r *DependencyGraphRepository) FailResolve(
	ctx context.Context,
	req domain.DependencyGraphResolveRequest,
	message string,
	retryAfter time.Time,
) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE dependency_graph_roots
		 SET status = 'failed', error = $1, updated_at = $2
		 WHERE tenant_id = $3 AND upstream_id = $4 AND package_name = $5 AND version = $6`,
		message,
		retryAfter,
		req.TenantID,
		req.Upstream.ID,
		req.Root.FullName(),
		req.Root.Version,
	)
	if err != nil {
		return fmt.Errorf("marking dependency graph failed: %w", err)
	}
	return nil
}

// LookupContext returns graph context for an artifact, classifying conflicting evidence as unknown.
func (r *DependencyGraphRepository) LookupContext(
	ctx context.Context,
	key domain.DependencyContextSummaryKey,
) (*domain.DependencyContext, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT context
		 FROM dependency_context_summaries
		 WHERE tenant_id = $1
		   AND organization_id = NULLIF($2, '')::uuid
		   AND team_id IS NOT DISTINCT FROM NULLIF($3, '')::uuid
		   AND upstream_id = $4
		   AND ecosystem = $5
		   AND namespace = $6
		   AND name = $7
		   AND version = $8
		   AND digest = $9`,
		key.TenantID,
		key.OrganizationID,
		key.TeamID,
		key.UpstreamID,
		key.Artifact.Ecosystem,
		key.Artifact.Namespace,
		key.Artifact.Name,
		key.Artifact.Version,
		key.Artifact.Digest,
	)
	if err != nil {
		return nil, fmt.Errorf("looking up dependency context: %w", err)
	}
	defer rows.Close()

	var contexts []domain.DependencyContext
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scanning dependency context: %w", err)
		}
		var dependencyContext domain.DependencyContext
		if err := json.Unmarshal(data, &dependencyContext); err != nil {
			return nil, fmt.Errorf("decoding dependency context: %w", err)
		}
		contexts = append(contexts, dependencyContext.Normalize())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating dependency contexts: %w", err)
	}
	if len(contexts) == 0 {
		return nil, domain.ErrArtifactNotFound
	}

	merged := mergeDependencyContexts(contexts)
	return &merged, nil
}

func dependencyGraphRootID(ctx context.Context, tx pgx.Tx, req domain.DependencyGraphResolveRequest) (string, error) {
	var rootID string
	err := tx.QueryRow(ctx,
		`SELECT id
		 FROM dependency_graph_roots
		 WHERE tenant_id = $1 AND upstream_id = $2 AND package_name = $3 AND version = $4
		 FOR UPDATE`,
		req.TenantID, req.Upstream.ID, req.Root.FullName(), req.Root.Version,
	).Scan(&rootID)
	if err != nil {
		return "", fmt.Errorf("loading dependency graph root: %w", err)
	}
	return rootID, nil
}

func insertDependencyContextSummary(
	ctx context.Context,
	tx pgx.Tx,
	req domain.DependencyGraphResolveRequest,
	rootID string,
	artifact domain.ArtifactIdentity,
	dependencyContext domain.DependencyContext,
) error {
	data, err := json.Marshal(dependencyContext.Normalize())
	if err != nil {
		return fmt.Errorf("marshalling dependency context summary: %w", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO dependency_context_summaries (root_id, tenant_id, upstream_id, ecosystem, namespace, name, version, digest, context)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		rootID,
		req.TenantID,
		req.Upstream.ID,
		artifact.Ecosystem,
		artifact.Namespace,
		artifact.Name,
		artifact.Version,
		artifact.Digest,
		data,
	); err != nil {
		return fmt.Errorf("inserting dependency context summary: %w", err)
	}
	return nil
}

func dependencyContextForNode(rootID string, node domain.DependencyGraphNode) domain.DependencyContext {
	scope := domain.DependencyScopeTransitive
	depTypes := node.DependencyTypes
	if node.MinDepth == 0 {
		scope = domain.DependencyScopeDirect
		if len(depTypes) == 0 {
			depTypes = []domain.DependencyType{domain.DependencyTypeProd}
		}
	}
	return domain.DependencyContext{
		Scope:           scope,
		DependencyTypes: depTypes,
		GraphIDs:        []string{rootID},
	}
}

func mergeDependencyContexts(contexts []domain.DependencyContext) domain.DependencyContext {
	scope := contexts[0].Scope
	var depTypes []domain.DependencyType
	var graphIDs []string
	for _, ctx := range contexts {
		ctx = ctx.Normalize()
		if ctx.Scope == domain.DependencyScopeUnknown || ctx.Scope != scope {
			return domain.NewUnknownDependencyContext()
		}
		depTypes = append(depTypes, ctx.DependencyTypes...)
		graphIDs = append(graphIDs, ctx.GraphIDs...)
	}
	return domain.DependencyContext{
		Scope:           scope,
		DependencyTypes: depTypes,
		GraphIDs:        graphIDs,
	}.Normalize()
}

func dependencyTypeStrings(values []domain.DependencyType) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		result = append(result, string(value))
	}
	return result
}
