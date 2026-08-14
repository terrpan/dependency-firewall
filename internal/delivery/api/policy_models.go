package api

import (
	"encoding/json"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type policyRequest struct {
	UpstreamID    *string                 `json:"upstream_id,omitempty"`
	WaiverMode    domain.PolicyWaiverMode `json:"waiver_mode,omitempty" enum:"none,approval_required"`
	Name          string                  `json:"name,omitempty" validate:"notblank"`
	Type          domain.PolicyType       `json:"type,omitempty" validate:"required,oneof=cvss_threshold minimum_age maximum_age block_mutable_tag scorecard license license_allowlist allowlist namespace_allowlist blocklist"`
	Action        domain.PolicyAction     `json:"action,omitempty" validate:"required,oneof=allow deny"`
	SchemaVersion int                     `json:"schema_version,omitempty" validate:"required,gte=1"`
	Target        *domain.PolicyTarget    `json:"target,omitempty"`
	Config        json.RawMessage         `json:"config,omitempty" validate:"required"`
	Priority      int                     `json:"priority,omitempty"`
	Enabled       bool                    `json:"enabled,omitempty"`
}

type policyRollbackRequest struct {
	Version int `json:"version,omitempty" validate:"required,gte=1"`
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
	ID       string `                     doc:"Policy identifier" path:"id"`
}

type updatePolicyInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `                     doc:"Policy identifier" path:"id"`
	Body     policyRequest
}

type rollbackPolicyInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `                     doc:"Policy identifier" path:"id"`
	Body     policyRollbackRequest
}

type deletePolicyInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Tenant identifier"`
	ID       string `                     doc:"Policy identifier"                                                    path:"id"`
	Force    bool   `                     doc:"Detach historical evaluation and decision references before deleting"           query:"force"`
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
