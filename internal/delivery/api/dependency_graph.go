package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// DependencyGraphHandler exposes resolved dependency graphs to the control-plane UI.
type DependencyGraphHandler struct {
	repository port.DependencyGraphRepository
	logger     *slog.Logger
}

// NewDependencyGraphHandler wires the handler to the repository it reads resolved graphs from. The handler is
// read-only: enqueueing, retrying or invalidating a graph root is not exposed over HTTP.
func NewDependencyGraphHandler(repository port.DependencyGraphRepository, logger *slog.Logger) *DependencyGraphHandler {
	return &DependencyGraphHandler{repository: repository, logger: logger}
}

// RegisterHumaRoutes registers the tenant-scoped graph list and snapshot operations on the control-plane API, including
// their documented error responses.
func (h *DependencyGraphHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-dependency-graphs",
		Method:      http.MethodGet,
		Path:        "/api/v1/dependency-graphs",
		Summary:     "List resolved dependency graphs",
		Description: "Lists tenant-scoped npm dependency graph roots.",
		Tags: []string{
			"dependency-graphs",
		},
		Errors: controlPlaneReadErrors(http.StatusBadRequest, http.StatusInternalServerError),
	}, h.list)
	huma.Register(api, huma.Operation{
		OperationID: "get-dependency-graph",
		Method:      http.MethodGet,
		Path:        "/api/v1/dependency-graphs/{id}",
		Summary:     "Get a resolved dependency graph",
		Description: "Returns one tenant-scoped npm dependency graph with nodes and edges.",
		Tags: []string{
			"dependency-graphs",
		},
		Errors: controlPlaneReadErrors(http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError),
	}, h.get)
	removeValidationResponse(api, "/api/v1/dependency-graphs", http.MethodGet)
	removeValidationResponse(api, "/api/v1/dependency-graphs/{id}", http.MethodGet)
}

type dependencyGraphListInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	Limit    int    `                     doc:"Maximum number of graph roots" query:"limit" minimum:"1" maximum:"500" default:"100"`
}

type dependencyGraphIDInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `                     doc:"Graph root identifier" path:"id"`
}

type dependencyGraphListOutput struct {
	Body []*DependencyGraphRootResponse
}
type dependencyGraphOutput struct{ Body *DependencyGraphResponse }

// DependencyGraphRootResponse is the wire form of one npm root package whose graph was requested, carrying its
// resolution status plus the graph hash or error message that explains the current state. Timestamps are RFC 3339 UTC.
type DependencyGraphRootResponse struct {
	ID          string  `json:"id"`
	TenantID    string  `json:"tenant_id"`
	UpstreamID  string  `json:"upstream_id"`
	PackageName string  `json:"package_name"`
	Version     string  `json:"version"`
	Status      string  `json:"status"`
	GraphHash   string  `json:"graph_hash,omitempty"`
	Error       string  `json:"error,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	ResolvedAt  *string `json:"resolved_at,omitempty"`
}

// DependencyGraphNodeResponse is the wire form of one package/version in a resolved graph. MinDepth is the shallowest
// distance from the root, which is what determines whether the package counts as a direct or transitive dependency.
type DependencyGraphNodeResponse struct {
	ID              string                   `json:"id"`
	Artifact        ArtifactIdentityResponse `json:"artifact"`
	MinDepth        int                      `json:"min_depth"`
	DependencyTypes []string                 `json:"dependency_types,omitempty"`
}

// DependencyGraphEdgeResponse is the wire form of one parent-to-child dependency relationship, referencing nodes by
// their identifiers so the UI can render the graph without duplicating artifact identity per edge.
type DependencyGraphEdgeResponse struct {
	ID             string `json:"id"`
	ParentNodeID   string `json:"parent_node_id"`
	ChildNodeID    string `json:"child_node_id"`
	DependencyType string `json:"dependency_type"`
}

// DependencyGraphResponse is a complete graph snapshot: the root and its lifecycle state together with every node and
// edge stored for it. Nodes and edges are empty until resolution completes.
type DependencyGraphResponse struct {
	Root  *DependencyGraphRootResponse   `json:"root"`
	Nodes []*DependencyGraphNodeResponse `json:"nodes"`
	Edges []*DependencyGraphEdgeResponse `json:"edges"`
}

func (h *DependencyGraphHandler) list(
	ctx context.Context,
	input *dependencyGraphListInput,
) (*dependencyGraphListOutput, error) {
	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()
	if input.TenantID == "" {
		return nil, huma.Error400BadRequest("missing X-Tenant-ID header")
	}
	roots, err := h.repository.ListRoots(ctx, input.TenantID, input.Limit)
	if err != nil {
		return nil, humaInternalError(
			ctx,
			h.logger,
			"listing dependency graphs",
			err,
			"failed to list dependency graphs",
		)
	}
	responses := make([]*DependencyGraphRootResponse, 0, len(roots))
	for i := range roots {
		responses = append(responses, toDependencyGraphRootResponse(roots[i]))
	}
	return &dependencyGraphListOutput{Body: responses}, nil
}

func (h *DependencyGraphHandler) get(
	ctx context.Context,
	input *dependencyGraphIDInput,
) (*dependencyGraphOutput, error) {
	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()
	if input.TenantID == "" {
		return nil, huma.Error400BadRequest("missing X-Tenant-ID header")
	}
	snapshot, err := h.repository.GetSnapshot(ctx, input.TenantID, input.ID)
	if err != nil {
		if errors.Is(err, domain.ErrArtifactNotFound) {
			return nil, huma.Error404NotFound("dependency graph not found")
		}
		return nil, humaInternalError(ctx, h.logger, "getting dependency graph", err, "failed to get dependency graph")
	}
	return &dependencyGraphOutput{Body: toDependencyGraphResponse(snapshot)}, nil
}

func toDependencyGraphRootResponse(root domain.DependencyGraphRoot) *DependencyGraphRootResponse {
	response := &DependencyGraphRootResponse{
		ID:          root.ID,
		TenantID:    root.TenantID,
		UpstreamID:  root.UpstreamID,
		PackageName: root.PackageName,
		Version:     root.Version,
		Status:      string(root.Status),
		GraphHash:   root.GraphHash,
		Error:       root.Error,
		CreatedAt:   root.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z07:00"),
		UpdatedAt:   root.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999Z07:00"),
	}
	if root.ResolvedAt != nil {
		value := root.ResolvedAt.UTC().Format("2006-01-02T15:04:05.999Z07:00")
		response.ResolvedAt = &value
	}
	return response
}

func toDependencyGraphResponse(snapshot *domain.DependencyGraphSnapshot) *DependencyGraphResponse {
	response := &DependencyGraphResponse{
		Root:  toDependencyGraphRootResponse(snapshot.Root),
		Nodes: make([]*DependencyGraphNodeResponse, 0, len(snapshot.Nodes)),
		Edges: make([]*DependencyGraphEdgeResponse, 0, len(snapshot.Edges)),
	}
	for _, node := range snapshot.Nodes {
		dependencyTypes := make([]string, 0, len(node.DependencyTypes))
		for _, value := range node.DependencyTypes {
			dependencyTypes = append(dependencyTypes, string(value))
		}
		response.Nodes = append(
			response.Nodes,
			&DependencyGraphNodeResponse{
				ID: node.ID,
				Artifact: ArtifactIdentityResponse{
					Ecosystem: string(node.Artifact.Ecosystem),
					Namespace: node.Artifact.Namespace,
					Name:      node.Artifact.Name,
					Version:   node.Artifact.Version,
					Digest:    node.Artifact.Digest,
				},
				MinDepth:        node.MinDepth,
				DependencyTypes: dependencyTypes,
			},
		)
	}
	for _, edge := range snapshot.Edges {
		response.Edges = append(
			response.Edges,
			&DependencyGraphEdgeResponse{
				ID:             edge.ID,
				ParentNodeID:   edge.ParentNodeID,
				ChildNodeID:    edge.ChildNodeID,
				DependencyType: string(edge.DependencyType),
			},
		)
	}
	return response
}
