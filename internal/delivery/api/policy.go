package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
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

type policyRequest struct {
	UpstreamID    *string             `json:"upstream_id,omitempty"`
	Name          string              `json:"name,omitempty" validate:"notblank"`
	Type          domain.PolicyType   `json:"type,omitempty" validate:"required,oneof=cvss_threshold minimum_age maximum_age block_mutable_tag license license_allowlist allowlist namespace_allowlist blocklist"`
	Action        domain.PolicyAction `json:"action,omitempty" validate:"required,oneof=allow deny"`
	SchemaVersion int                 `json:"schema_version,omitempty" validate:"required,gte=1"`
	Config        json.RawMessage     `json:"config,omitempty" validate:"required"`
	Priority      int                 `json:"priority,omitempty"`
	Enabled       bool                `json:"enabled,omitempty"`
}

type policyRollbackRequest struct {
	Version int `json:"version,omitempty" validate:"required,gte=1"`
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

type policyTypesOutput struct {
	Body []*PolicyTypeResponse
}

type policyHeaderInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
}

type createPolicyInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	Body     policyRequest
}

type policyIDInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `path:"id" doc:"Policy identifier"`
}

type updatePolicyInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `path:"id" doc:"Policy identifier"`
	Body     policyRequest
}

type rollbackPolicyInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `path:"id" doc:"Policy identifier"`
	Body     policyRollbackRequest
}

type deletePolicyInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `path:"id" doc:"Policy identifier"`
	Force    bool   `query:"force" doc:"Detach historical evaluation and decision references before deleting"`
}

type policyOutput struct {
	Body *PolicyResponse
}

type policyListOutput struct {
	Body []*PolicyResponse
}

type policyVersionListOutput struct {
	Body []*PolicyVersionResponse
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

func (h *PolicyHandler) createPolicy(ctx context.Context, rawTenantID string, req policyRequest) (*PolicyResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	config, err := corepolicy.DecodeConfigJSON(req.Type, req.SchemaVersion, req.Config)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	p := &domain.Policy{
		TenantID:      tenantID,
		UpstreamID:    trimOptionalString(req.UpstreamID),
		Name:          req.Name,
		Type:          req.Type,
		Action:        req.Action,
		SchemaVersion: req.SchemaVersion,
		Config:        config,
		Priority:      req.Priority,
		Enabled:       req.Enabled,
	}

	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	if err := h.policies.Create(ctx, p); err != nil {
		if errors.Is(err, domain.ErrInvalidPolicy) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrPolicyUpstreamIncompatible) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrPolicyNameConflict) {
			return nil, huma.Error409Conflict("policy name already exists")
		}
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			return nil, huma.Error400BadRequest("policy upstream not found")
		}
		h.logger.Error("creating policy", "error", err, "tenant_id", tenantID)
		return nil, huma.Error500InternalServerError("failed to create policy")
	}

	return toPolicyResponse(p), nil
}

func (h *PolicyHandler) listPolicies(ctx context.Context, rawTenantID string) ([]*PolicyResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	policies, err := h.policies.ListByTenant(ctx, tenantID)
	if err != nil {
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
		}
		h.logger.Error("listing policies", "error", err, "tenant_id", tenantID)
		return nil, huma.Error500InternalServerError("failed to list policies")
	}
	return toPoliciesResponse(policies), nil
}

func (h *PolicyHandler) listPolicyVersions(ctx context.Context, rawTenantID, id string) ([]*PolicyVersionResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	versions, err := h.policies.ListVersions(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			return nil, huma.Error404NotFound("policy not found")
		}
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
		}
		h.logger.Error("listing policy versions", "error", err, "tenant_id", tenantID, "policy_id", id)
		return nil, huma.Error500InternalServerError("failed to list policy versions")
	}
	return toPolicyVersionsResponse(versions), nil
}

func (h *PolicyHandler) getPolicy(ctx context.Context, rawTenantID, id string) (*PolicyResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	p, err := h.policies.GetByID(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			return nil, huma.Error404NotFound("policy not found")
		}
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
		}
		h.logger.Error("getting policy", "error", err, "tenant_id", tenantID, "policy_id", id)
		return nil, huma.Error500InternalServerError("failed to get policy")
	}
	return toPolicyResponse(p), nil
}

func (h *PolicyHandler) updatePolicy(ctx context.Context, rawTenantID, id string, req policyRequest) (*PolicyResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	config, err := corepolicy.DecodeConfigJSON(req.Type, req.SchemaVersion, req.Config)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	p := &domain.Policy{
		ID:            id,
		TenantID:      tenantID,
		UpstreamID:    trimOptionalString(req.UpstreamID),
		Name:          req.Name,
		Type:          req.Type,
		Action:        req.Action,
		SchemaVersion: req.SchemaVersion,
		Config:        config,
		Priority:      req.Priority,
		Enabled:       req.Enabled,
	}

	if err := h.policies.Update(ctx, p); err != nil {
		if errors.Is(err, domain.ErrInvalidPolicy) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrPolicyUpstreamIncompatible) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrPolicyNameConflict) {
			return nil, huma.Error409Conflict("policy name already exists")
		}
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			return nil, huma.Error400BadRequest("policy upstream not found")
		}
		if errors.Is(err, domain.ErrPolicyNotFound) {
			return nil, huma.Error404NotFound("policy not found")
		}
		h.logger.Error("updating policy", "error", err, "tenant_id", tenantID, "policy_id", id)
		return nil, huma.Error500InternalServerError("failed to update policy")
	}
	return toPolicyResponse(p), nil
}

func (h *PolicyHandler) rollbackPolicy(ctx context.Context, rawTenantID, id string, req policyRollbackRequest) (*PolicyResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	p, err := h.policies.RollbackToVersion(ctx, tenantID, id, req.Version)
	if err != nil {
		if errors.Is(err, domain.ErrPolicyNotFound) {
			return nil, huma.Error404NotFound("policy not found")
		}
		if errors.Is(err, domain.ErrPolicyVersionNotFound) {
			return nil, huma.Error404NotFound("policy version not found")
		}
		if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains deprecated stored policies; run the policy data migration")
		}
		if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
			return nil, huma.NewError(http.StatusConflict, "tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data")
		}
		if errors.Is(err, domain.ErrInvalidPolicy) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrPolicyUpstreamIncompatible) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		h.logger.Error("rolling back policy", "error", err, "tenant_id", tenantID, "policy_id", id)
		return nil, huma.Error500InternalServerError("failed to rollback policy")
	}

	return toPolicyResponse(p), nil
}

func (h *PolicyHandler) deletePolicy(ctx context.Context, rawTenantID, id string, force bool) error {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return huma.Error400BadRequest(err.Error())
	}

	if err := h.policies.Delete(ctx, tenantID, id, force); err != nil {
		if errors.Is(err, domain.ErrPolicyDeleteEnabled) {
			return huma.Error409Conflict("disable policy before deleting it")
		}
		if errors.Is(err, domain.ErrPolicyInUse) {
			return huma.Error409Conflict("policy has recorded evaluations or decisions")
		}
		if errors.Is(err, domain.ErrPolicyNotFound) {
			return huma.Error404NotFound("policy not found")
		}
		h.logger.Error("deleting policy", "error", err, "tenant_id", tenantID, "policy_id", id)
		return huma.Error500InternalServerError("failed to delete policy")
	}
	return nil
}

func parseMediaType(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", errors.New("invalid Content-Type header")
	}
	return mediaType, nil
}

func isSupportedPolicyImportContentType(mediaType string) bool {
	switch mediaType {
	case "application/json", "application/x-yaml", "application/yaml", "text/yaml", "text/x-yaml":
		return true
	default:
		return false
	}
}

func trimOptionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
