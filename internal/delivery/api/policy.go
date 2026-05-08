package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// PolicyHandler handles policy CRUD and import endpoints.
type PolicyHandler struct {
	policies *service.PolicyService
	logger   *slog.Logger
}

// NewPolicyHandler creates a new PolicyHandler.
func NewPolicyHandler(policies *service.PolicyService, logger *slog.Logger) *PolicyHandler {
	return &PolicyHandler{policies: policies, logger: logger}
}

// RegisterRoutes registers policy API routes on the given mux.
func (h *PolicyHandler) RegisterRoutes(mux *http.ServeMux) {
}

// RegisterHumaRoutes registers policy metadata routes on the control-plane Huma API.
func (h *PolicyHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-policy",
		Method:        http.MethodPost,
		Path:          "/api/v1/policies",
		Summary:       "Create a policy",
		Description:   "Creates a tenant-scoped policy definition used during proxy policy evaluation.",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"policies"},
		Errors:        []int{http.StatusBadRequest, http.StatusConflict, http.StatusInternalServerError},
	}, h.create)
	huma.Register(api, huma.Operation{
		OperationID: "list-policies",
		Method:      http.MethodGet,
		Path:        "/api/v1/policies",
		Summary:     "List policies",
		Description: "Lists the policies currently configured for the tenant.",
		Tags:        []string{"policies"},
		Errors:      []int{http.StatusBadRequest, http.StatusConflict, http.StatusInternalServerError},
	}, h.list)
	huma.Register(api, huma.Operation{
		OperationID: "get-policy",
		Method:      http.MethodGet,
		Path:        "/api/v1/policies/{id}",
		Summary:     "Get a policy by ID",
		Description: "Returns one tenant-scoped policy definition by ID.",
		Tags:        []string{"policies"},
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError},
	}, h.get)
	huma.Register(api, huma.Operation{
		OperationID: "update-policy",
		Method:      http.MethodPut,
		Path:        "/api/v1/policies/{id}",
		Summary:     "Update a policy",
		Description: "Updates an existing tenant-scoped policy definition.",
		Tags:        []string{"policies"},
		Errors:      []int{http.StatusBadRequest, http.StatusConflict, http.StatusNotFound, http.StatusInternalServerError},
	}, h.update)
	huma.Register(api, huma.Operation{
		OperationID:   "delete-policy",
		Method:        http.MethodDelete,
		Path:          "/api/v1/policies/{id}",
		Summary:       "Delete a policy",
		Description:   "Deletes a tenant-scoped policy definition by ID. Use force=true to detach historical evaluation and decision references first.",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"policies"},
		Errors:        []int{http.StatusBadRequest, http.StatusConflict, http.StatusNotFound, http.StatusInternalServerError},
	}, h.delete)
	huma.Register(api, huma.Operation{
		OperationID: "list-policy-versions",
		Method:      http.MethodGet,
		Path:        "/api/v1/policies/{id}/versions",
		Summary:     "List policy versions",
		Description: "Lists the retained version history for a tenant-scoped policy definition.",
		Tags:        []string{"policies"},
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError},
	}, h.listVersions)
	huma.Register(api, huma.Operation{
		OperationID: "rollback-policy",
		Method:      http.MethodPost,
		Path:        "/api/v1/policies/{id}/rollback",
		Summary:     "Rollback a policy",
		Description: "Restores a tenant-scoped policy definition from a retained version snapshot.",
		Tags:        []string{"policies"},
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError},
	}, h.rollback)
	huma.Register(api, huma.Operation{
		OperationID: "list-policy-types",
		Method:      http.MethodGet,
		Path:        "/api/v1/policy-types",
		Summary:     "List policy types",
		Description: "Lists the supported policy types, actions, schema versions, and authoring metadata available to the control plane.",
		Tags:        []string{"policies"},
	}, h.listTypesHuma)
	huma.Register(api, huma.Operation{
		OperationID: "import-policies",
		Method:      http.MethodPost,
		Path:        "/api/v1/policies/import",
		Summary:     "Import policies",
		Description: "Imports a tenant policy document from YAML or JSON and upserts policies by name within the tenant.",
		Tags:        []string{"policies"},
		Errors:      []int{http.StatusBadRequest, http.StatusConflict, http.StatusUnsupportedMediaType, http.StatusInternalServerError},
	}, h.importPoliciesHuma)
	removeValidationResponse(api, "/api/v1/policies", http.MethodGet, http.MethodPost)
	removeValidationResponse(api, "/api/v1/policies/{id}", http.MethodGet, http.MethodPut, http.MethodDelete)
	removeValidationResponse(api, "/api/v1/policies/{id}/versions", http.MethodGet)
	removeValidationResponse(api, "/api/v1/policies/{id}/rollback", http.MethodPost)
	removeValidationResponse(api, "/api/v1/policy-types", http.MethodGet)
	removeValidationResponse(api, "/api/v1/policies/import", http.MethodPost)
	setRequestBodyContentTypes(api, "/api/v1/policies/import", http.MethodPost,
		"application/json",
		"application/x-yaml",
		"application/yaml",
		"text/yaml",
		"text/x-yaml",
	)
}

func (h *PolicyHandler) listTypesHuma(context.Context, *struct{}) (*policyTypesOutput, error) {
	return &policyTypesOutput{Body: toPolicyTypesResponse(h.policies.ListTypes())}, nil
}

func (h *PolicyHandler) create(ctx context.Context, input *createPolicyInput) (*policyOutput, error) {
	resp, err := h.createPolicy(ctx, input.TenantID, input.Body)
	if err != nil {
		return nil, err
	}
	return &policyOutput{Body: resp}, nil
}

func (h *PolicyHandler) list(ctx context.Context, input *policyHeaderInput) (*policyListOutput, error) {
	resp, err := h.listPolicies(ctx, input.TenantID)
	if err != nil {
		return nil, err
	}
	return &policyListOutput{Body: resp}, nil
}

func (h *PolicyHandler) listVersions(ctx context.Context, input *policyIDInput) (*policyVersionListOutput, error) {
	resp, err := h.listPolicyVersions(ctx, input.TenantID, input.ID)
	if err != nil {
		return nil, err
	}
	return &policyVersionListOutput{Body: resp}, nil
}

func (h *PolicyHandler) get(ctx context.Context, input *policyIDInput) (*policyOutput, error) {
	resp, err := h.getPolicy(ctx, input.TenantID, input.ID)
	if err != nil {
		return nil, err
	}
	return &policyOutput{Body: resp}, nil
}

func (h *PolicyHandler) update(ctx context.Context, input *updatePolicyInput) (*policyOutput, error) {
	resp, err := h.updatePolicy(ctx, input.TenantID, input.ID, input.Body)
	if err != nil {
		return nil, err
	}
	return &policyOutput{Body: resp}, nil
}

func (h *PolicyHandler) rollback(ctx context.Context, input *rollbackPolicyInput) (*policyOutput, error) {
	resp, err := h.rollbackPolicy(ctx, input.TenantID, input.ID, input.Body)
	if err != nil {
		return nil, err
	}
	return &policyOutput{Body: resp}, nil
}

func (h *PolicyHandler) delete(ctx context.Context, input *deletePolicyInput) (*struct{}, error) {
	if err := h.deletePolicy(ctx, input.TenantID, input.ID, input.Force); err != nil {
		return nil, err
	}
	return nil, nil
}
