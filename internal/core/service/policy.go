package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// PolicyService owns policy management workflows for the control plane.
type PolicyService struct {
	repo          port.PolicyRepository
	revisions     port.PolicyRevisionRepository
	decisionCache port.DecisionCache
	upstreams     port.UpstreamRepository
}

// NewPolicyService creates a new PolicyService.
func NewPolicyService(
	repo port.PolicyRepository,
	revisions port.PolicyRevisionRepository,
	decisionCache port.DecisionCache,
	upstreams port.UpstreamRepository,
) *PolicyService {
	return &PolicyService{
		repo:          repo,
		revisions:     revisions,
		decisionCache: decisionCache,
		upstreams:     upstreams,
	}
}

// ListTypes returns supported policy types and their help metadata.
func (s *PolicyService) ListTypes() []domain.PolicyTypeDescriptor {
	return policy.TypeCatalog()
}

// Create creates a policy for a tenant.
func (s *PolicyService) Create(ctx context.Context, policyDef *domain.Policy) error {
	if policyDef.SchemaVersion == 0 {
		normalizedSchemaVersion, err := policy.NormalizeSchemaVersion(policyDef.Type, policyDef.SchemaVersion)
		if err != nil {
			return err
		}
		policyDef.SchemaVersion = normalizedSchemaVersion
	}
	if err := policy.ValidatePolicy(*policyDef); err != nil {
		return err
	}
	if err := s.validateUpstreamScope(ctx, policyDef.TenantID, policyDef.UpstreamID, policyDef.Type); err != nil {
		return err
	}
	if err := s.repo.Create(ctx, policyDef); err != nil {
		return fmt.Errorf("creating policy: %w", err)
	}
	if err := s.finalizeTenantMutation(ctx, policyDef.TenantID); err != nil {
		return fmt.Errorf("finalizing policy creation: %w", err)
	}
	return nil
}

// GetByID returns a policy for a tenant.
func (s *PolicyService) GetByID(ctx context.Context, tenantID, id string) (*domain.Policy, error) {
	policyDef, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("getting policy: %w", err)
	}
	if err := policy.ValidatePolicy(*policyDef); err != nil {
		return nil, fmt.Errorf("validating loaded policy: %w", err)
	}
	return policyDef, nil
}

// ListByTenant returns policies for a tenant.
func (s *PolicyService) ListByTenant(ctx context.Context, tenantID string) ([]domain.Policy, error) {
	policies, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	if err := policy.ValidatePolicies(policies); err != nil {
		return nil, fmt.Errorf("validating loaded policies: %w", err)
	}
	return policies, nil
}

// ListVersions returns the retained version history for a policy.
func (s *PolicyService) ListVersions(ctx context.Context, tenantID, policyID string) ([]domain.PolicyVersion, error) {
	versions, err := s.repo.ListVersions(ctx, tenantID, policyID, domain.MaxRetainedPolicyVersions)
	if err != nil {
		return nil, fmt.Errorf("listing policy versions: %w", err)
	}

	for i := range versions {
		if err := policy.ValidatePolicy(domain.Policy{
			ID:            versions[i].PolicyID,
			TenantID:      tenantID,
			UpstreamID:    versions[i].UpstreamID,
			Name:          versions[i].Name,
			Type:          versions[i].Type,
			Action:        versions[i].Action,
			SchemaVersion: versions[i].SchemaVersion,
			Config:        versions[i].Config,
			Priority:      versions[i].Priority,
			Enabled:       versions[i].Enabled,
			Version:       versions[i].Version,
		}); err != nil {
			return nil, fmt.Errorf("validating stored policy version %d: %w", versions[i].Version, err)
		}
	}

	return versions, nil
}

// Update updates a policy for a tenant.
func (s *PolicyService) Update(ctx context.Context, policyDef *domain.Policy) error {
	if policyDef.SchemaVersion == 0 {
		normalizedSchemaVersion, err := policy.NormalizeSchemaVersion(policyDef.Type, policyDef.SchemaVersion)
		if err != nil {
			return err
		}
		policyDef.SchemaVersion = normalizedSchemaVersion
	}
	if err := policy.ValidatePolicy(*policyDef); err != nil {
		return err
	}
	if err := s.validateUpstreamScope(ctx, policyDef.TenantID, policyDef.UpstreamID, policyDef.Type); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, policyDef); err != nil {
		return fmt.Errorf("updating policy: %w", err)
	}
	if err := s.finalizeTenantMutation(ctx, policyDef.TenantID); err != nil {
		return fmt.Errorf("finalizing policy update: %w", err)
	}
	return nil
}

// RollbackToVersion restores a policy from a retained version snapshot.
func (s *PolicyService) RollbackToVersion(
	ctx context.Context,
	tenantID, policyID string,
	version int,
) (*domain.Policy, error) {
	versions, err := s.repo.ListVersions(ctx, tenantID, policyID, domain.MaxRetainedPolicyVersions)
	if err != nil {
		return nil, fmt.Errorf("listing policy versions for rollback: %w", err)
	}
	for i := range versions {
		if versions[i].Version != version {
			continue
		}
		if err := s.validateUpstreamScope(ctx, tenantID, versions[i].UpstreamID, versions[i].Type); err != nil {
			return nil, fmt.Errorf("validating rolled back policy upstream: %w", err)
		}
		break
	}

	policyDef, err := s.repo.RollbackToVersion(ctx, tenantID, policyID, version)
	if err != nil {
		return nil, fmt.Errorf("rolling back policy: %w", err)
	}
	if err := policy.ValidatePolicy(*policyDef); err != nil {
		return nil, fmt.Errorf("validating rolled back policy: %w", err)
	}
	if err := s.finalizeTenantMutation(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("finalizing policy rollback: %w", err)
	}
	return policyDef, nil
}

// Delete removes a policy for a tenant.
func (s *PolicyService) Delete(ctx context.Context, tenantID, id string, force bool) error {
	policyDef, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("getting policy for delete: %w", err)
	}
	if policyDef.Enabled {
		return domain.ErrPolicyDeleteEnabled
	}

	if err := s.repo.Delete(ctx, tenantID, id, force); err != nil {
		return fmt.Errorf("deleting policy: %w", err)
	}
	if err := s.finalizeTenantMutation(ctx, tenantID); err != nil {
		return fmt.Errorf("finalizing policy delete: %w", err)
	}
	return nil
}

// ImportPolicies persists typed policy definitions for a tenant. The tenant
// argument is authoritative and overrides tenant IDs on imported policies.
func (s *PolicyService) ImportPolicies(ctx context.Context, tenantID string, imported []domain.Policy) (int, error) {
	policies := make([]domain.Policy, len(imported))
	for i := range imported {
		policies[i] = imported[i]
		policies[i].TenantID = tenantID
		if policies[i].Version == 0 {
			policies[i].Version = 1
		}
		if err := s.validateUpstreamScope(ctx, tenantID, policies[i].UpstreamID, policies[i].Type); err != nil {
			return 0, fmt.Errorf("validating imported policy %q upstream: %w", policies[i].Name, err)
		}
	}

	if err := policy.ValidatePolicies(policies); err != nil {
		return 0, fmt.Errorf("validating imported policies: %w", err)
	}

	existingPolicies, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("listing existing policies for import: %w", err)
	}

	existingByName := make(map[string]domain.Policy, len(existingPolicies))
	for i := range existingPolicies {
		existingByName[existingPolicies[i].Name] = existingPolicies[i]
	}

	mutated := false
	for i := range policies {
		persistErr := func() error {
			existing, found := existingByName[policies[i].Name]
			if !found {
				if err := s.repo.Create(ctx, &policies[i]); err != nil {
					return err
				}
				existingByName[policies[i].Name] = policies[i]
				return nil
			}

			policies[i].ID = existing.ID
			if err := s.repo.Update(ctx, &policies[i]); err != nil {
				return err
			}
			existingByName[policies[i].Name] = policies[i]
			return nil
		}()
		if persistErr != nil {
			if mutated {
				if finalizeErr := s.finalizeTenantMutation(ctx, tenantID); finalizeErr != nil {
					return 0, fmt.Errorf(
						"persisting imported policy %q: %w; finalizing partial import: %v",
						policies[i].Name,
						persistErr,
						finalizeErr,
					)
				}
				return 0, fmt.Errorf(
					"persisting imported policy %q: %w; partial import already recorded a new policy revision and invalidated cached decisions",
					policies[i].Name,
					persistErr,
				)
			}
			return 0, fmt.Errorf("persisting imported policy %q: %w", policies[i].Name, persistErr)
		}
		mutated = true
	}

	if mutated {
		if err := s.finalizeTenantMutation(ctx, tenantID); err != nil {
			return 0, fmt.Errorf("finalizing imported policies: %w", err)
		}
	}

	return len(policies), nil
}

func (s *PolicyService) validateUpstreamScope(
	ctx context.Context,
	tenantID, upstreamID string,
	policyType domain.PolicyType,
) error {
	if upstreamID == "" || s.upstreams == nil {
		return nil
	}
	upstream, err := s.upstreams.GetByID(ctx, tenantID, upstreamID)
	if err != nil {
		return err
	}
	if err := policy.ValidateUpstreamCompatibility(policyType, *upstream); err != nil {
		return err
	}
	return nil
}

func (s *PolicyService) finalizeTenantMutation(ctx context.Context, tenantID string) error {
	var errs []error

	policies, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		errs = append(errs, fmt.Errorf("listing tenant policies for revision: %w", err))
	} else {
		if validateErr := policy.ValidatePolicies(policies); validateErr != nil {
			errs = append(errs, fmt.Errorf("validating tenant policies for revision: %w", validateErr))
		}
		hash, hashErr := policy.HashPolicies(policies)
		if hashErr != nil {
			errs = append(errs, fmt.Errorf("hashing tenant policy set: %w", hashErr))
		} else if len(errs) == 0 {
			revision := &domain.PolicySetRevision{
				TenantID:   tenantID,
				PolicyHash: hash,
			}
			if revisionErr := s.revisions.Create(ctx, revision); revisionErr != nil {
				errs = append(errs, fmt.Errorf("recording tenant policy revision: %w", revisionErr))
			}
		}
	}

	if err := s.decisionCache.InvalidateTenant(ctx, tenantID); err != nil {
		errs = append(errs, fmt.Errorf("invalidating tenant decision cache: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
