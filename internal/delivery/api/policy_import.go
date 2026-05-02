package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"gopkg.in/yaml.v3"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

type importPoliciesInput struct {
	TenantID    string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ContentType string `header:"Content-Type" hidden:"true"`
	RawBody     []byte
}

type importPoliciesOutput struct {
	Body policyImportResponse
}

type policyImportDocument struct {
	TenantID string                   `json:"tenant_id" yaml:"tenant_id"`
	Policies []policyImportDefinition `json:"policies" yaml:"policies"`
}

type policyImportDefinition struct {
	UpstreamID    *string        `json:"upstream_id" yaml:"upstream_id"`
	Name          string         `json:"name" yaml:"name"`
	Type          string         `json:"type" yaml:"type"`
	SchemaVersion *int           `json:"schema_version" yaml:"schema_version"`
	Action        string         `json:"action" yaml:"action"`
	Priority      *int           `json:"priority" yaml:"priority"`
	Config        map[string]any `json:"config" yaml:"config"`
	Enabled       *bool          `json:"enabled" yaml:"enabled"`
}

func (h *PolicyHandler) importPoliciesHuma(ctx context.Context, input *importPoliciesInput) (*importPoliciesOutput, error) {
	tenantID, err := tenantIDFromValue(input.TenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	mediaType, err := parseMediaType(input.ContentType)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if mediaType != "" && !isSupportedPolicyImportContentType(mediaType) {
		return nil, huma.NewError(http.StatusUnsupportedMediaType, "unsupported Content-Type for policy import")
	}

	policies, err := decodeImportedPolicies(input.RawBody, tenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	count, err := h.policies.ImportPolicies(ctx, tenantID, policies)
	if err != nil {
		if errorsIsImportBadRequest(err) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if isPolicyNameConflict(err) {
			return nil, huma.Error409Conflict("policy name already exists")
		}
		h.logger.Error("importing policies", "error", err, "tenant_id", tenantID)
		return nil, huma.Error500InternalServerError("failed to import policies")
	}

	return &importPoliciesOutput{
		Body: policyImportResponse{Imported: count},
	}, nil
}

func decodeImportedPolicies(data []byte, tenantID string) ([]domain.Policy, error) {
	document, err := parsePolicyImportDocument(data)
	if err != nil {
		return nil, err
	}

	policies, err := corepolicy.ToDomainPoliciesForTenant(document.toCorePolicyFile(), tenantID)
	if err != nil {
		return nil, fmt.Errorf("converting policy document: %w", err)
	}
	return policies, nil
}

func parsePolicyImportDocument(data []byte) (*policyImportDocument, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty policy document", domain.ErrInvalidPolicy)
	}

	var document policyImportDocument
	if looksLikeJSONDocument(trimmed) {
		if err := json.Unmarshal(trimmed, &document); err != nil {
			return nil, fmt.Errorf("parsing policy JSON: %w", err)
		}
		return &document, nil
	}

	if err := yaml.Unmarshal(trimmed, &document); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	return &document, nil
}

func (d *policyImportDocument) toCorePolicyFile() *corepolicy.PolicyFile {
	file := &corepolicy.PolicyFile{
		TenantID: d.TenantID,
		Policies: make([]corepolicy.PolicyDef, len(d.Policies)),
	}
	for i := range d.Policies {
		file.Policies[i] = corepolicy.PolicyDef{
			Name:          d.Policies[i].Name,
			UpstreamID:    d.Policies[i].UpstreamID,
			Type:          d.Policies[i].Type,
			SchemaVersion: d.Policies[i].SchemaVersion,
			Action:        d.Policies[i].Action,
			Priority:      d.Policies[i].Priority,
			Config:        d.Policies[i].Config,
			Enabled:       d.Policies[i].Enabled,
		}
	}
	return file
}

func looksLikeJSONDocument(data []byte) bool {
	return len(data) > 0 && (data[0] == '{' || data[0] == '[')
}

func errorsIsImportBadRequest(err error) bool {
	return errors.Is(err, domain.ErrInvalidPolicy) ||
		errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) ||
		errors.Is(err, domain.ErrUpstreamNotFound) ||
		errors.Is(err, domain.ErrPolicyUpstreamIncompatible)
}

func isPolicyNameConflict(err error) bool {
	return errors.Is(err, domain.ErrPolicyNameConflict)
}
