package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

func (h *PolicyHandler) createPolicy(
	ctx context.Context,
	rawTenantID string,
	req policyRequest,
) (*PolicyResponse, error) {
	policy, err := policyFromRequest(rawTenantID, "", req)
	if err != nil {
		return nil, err
	}

	if err := h.policies.Create(ctx, policy); err != nil {
		return nil, h.policyMutationError(
			ctx,
			policy.TenantID,
			"",
			false,
			"creating policy",
			"failed to create policy",
			err,
		)
	}

	return toPolicyResponse(policy), nil
}

func (h *PolicyHandler) listPolicies(ctx context.Context, rawTenantID string) ([]*PolicyResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()

	policies, err := h.policies.ListByTenant(ctx, tenantID)
	if err != nil {
		if conflict := storedPolicyConflict(err); conflict != nil {
			return nil, conflict
		}
		return nil, humaInternalError(
			ctx,
			h.logger,
			"listing policies",
			err,
			"failed to list policies",
			"tenant_id",
			tenantID,
		)
	}
	return toPoliciesResponse(policies), nil
}

func (h *PolicyHandler) listPolicyVersions(
	ctx context.Context,
	rawTenantID, id string,
) ([]*PolicyVersionResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()

	versions, err := h.policies.ListVersions(ctx, tenantID, id)
	if err != nil {
		return nil, h.policyReadError(
			ctx,
			tenantID,
			id,
			"listing policy versions",
			"failed to list policy versions",
			err,
		)
	}
	return toPolicyVersionsResponse(versions), nil
}

func (h *PolicyHandler) getPolicy(ctx context.Context, rawTenantID, id string) (*PolicyResponse, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	ctx, cancel := withControlPlaneReadTimeout(ctx)
	defer cancel()

	policy, err := h.policies.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, h.policyReadError(ctx, tenantID, id, "getting policy", "failed to get policy", err)
	}
	return toPolicyResponse(policy), nil
}

func (h *PolicyHandler) updatePolicy(
	ctx context.Context,
	rawTenantID, id string,
	req policyRequest,
) (*PolicyResponse, error) {
	policy, err := policyFromRequest(rawTenantID, id, req)
	if err != nil {
		return nil, err
	}

	if err := h.policies.Update(ctx, policy); err != nil {
		return nil, h.policyMutationError(
			ctx,
			policy.TenantID,
			id,
			true,
			"updating policy",
			"failed to update policy",
			err,
		)
	}
	return toPolicyResponse(policy), nil
}

func policyFromRequest(rawTenantID, id string, req policyRequest) (*domain.Policy, error) {
	tenantID, err := tenantIDFromValue(rawTenantID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if err := validateRequest(req); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if err := req.Target.Validate(); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if req.Target != nil {
		req.Target.Normalize()
	}

	config, err := corepolicy.DecodeConfigJSON(req.Type, req.SchemaVersion, req.Config)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	return &domain.Policy{
		ID:            id,
		TenantID:      tenantID,
		WaiverMode:    req.WaiverMode,
		UpstreamID:    trimOptionalString(req.UpstreamID),
		Name:          req.Name,
		Type:          req.Type,
		Action:        req.Action,
		SchemaVersion: req.SchemaVersion,
		Target:        req.Target,
		Config:        config,
		Priority:      req.Priority,
		Enabled:       req.Enabled,
	}, nil
}

func (h *PolicyHandler) policyMutationError(
	ctx context.Context,
	tenantID, policyID string,
	includeNotFound bool,
	logMessage, clientMessage string,
	err error,
) error {
	if errors.Is(err, domain.ErrInvalidPolicy) {
		return huma.Error400BadRequest(err.Error())
	}
	if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
		return huma.Error400BadRequest(err.Error())
	}
	if errors.Is(err, domain.ErrPolicyUpstreamIncompatible) {
		return huma.Error400BadRequest(err.Error())
	}
	if errors.Is(err, domain.ErrPolicyNameConflict) {
		return huma.Error409Conflict("policy name already exists")
	}
	if errors.Is(err, domain.ErrUpstreamNotFound) {
		return huma.Error400BadRequest("policy upstream not found")
	}
	if includeNotFound && errors.Is(err, domain.ErrPolicyNotFound) {
		return huma.Error404NotFound("policy not found")
	}

	attrs := []any{"tenant_id", tenantID}
	if includeNotFound {
		attrs = append(attrs, "policy_id", policyID)
	}
	return humaInternalError(ctx, h.logger, logMessage, err, clientMessage, attrs...)
}

func (h *PolicyHandler) policyReadError(
	ctx context.Context,
	tenantID, policyID, logMessage, clientMessage string,
	err error,
) error {
	if errors.Is(err, domain.ErrPolicyNotFound) {
		return huma.Error404NotFound("policy not found")
	}
	if conflict := storedPolicyConflict(err); conflict != nil {
		return conflict
	}
	return humaInternalError(
		ctx,
		h.logger,
		logMessage,
		err,
		clientMessage,
		"tenant_id",
		tenantID,
		"policy_id",
		policyID,
	)
}

func storedPolicyConflict(err error) error {
	if errors.Is(err, domain.ErrDeprecatedPolicyConfig) {
		return huma.NewError(
			http.StatusConflict,
			"tenant contains deprecated stored policies; run the policy data migration",
		)
	}
	if errors.Is(err, domain.ErrUnsupportedPolicySchemaVersion) {
		return huma.NewError(
			http.StatusConflict,
			"tenant contains policies with an unsupported schema_version; upgrade the service or migrate policy data",
		)
	}
	return nil
}

func (h *PolicyHandler) rollbackPolicy(
	ctx context.Context,
	rawTenantID, id string,
	req policyRollbackRequest,
) (*PolicyResponse, error) {
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
		if conflict := storedPolicyConflict(err); conflict != nil {
			return nil, conflict
		}
		if errors.Is(err, domain.ErrInvalidPolicy) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, domain.ErrPolicyUpstreamIncompatible) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		return nil, humaInternalError(
			ctx,
			h.logger,
			"rolling back policy",
			err,
			"failed to rollback policy",
			"tenant_id",
			tenantID,
			"policy_id",
			id,
		)
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
		return humaInternalError(
			ctx,
			h.logger,
			"deleting policy",
			err,
			"failed to delete policy",
			"tenant_id",
			tenantID,
			"policy_id",
			id,
		)
	}
	return nil
}
