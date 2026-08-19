package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

// ListVersions returns retained versions for a policy, newest first.
func (r *PolicyRepository) ListVersions(
	ctx context.Context,
	tenantID, policyID string,
	limit int,
) ([]domain.PolicyVersion, error) {
	if limit <= 0 {
		limit = retainedPolicyVersionCount
	}

	rows, err := r.pool.Query(
		ctx,
		`SELECT pv.policy_id, pv.version, pv.upstream_id, pv.name, pv.type, pv.action, pv.schema_version, pv.config, pv.target, pv.priority, pv.enabled, pv.created_at
		 FROM policy_versions pv
		 JOIN policies p ON p.id = pv.policy_id
		 WHERE p.tenant_id = $1 AND pv.policy_id = $2
		 ORDER BY pv.version DESC
		 LIMIT $3`,
		tenantID,
		policyID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("listing policy versions: %w", err)
	}
	defer rows.Close()

	versions := []domain.PolicyVersion{}
	for rows.Next() {
		version, err := scanPolicyVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating policy version rows: %w", err)
	}
	if len(versions) == 0 {
		if _, err := r.GetByID(ctx, tenantID, policyID); err != nil {
			return nil, err
		}
	}
	return versions, nil
}

// RollbackToVersion restores a policy from a retained snapshot and creates a new current version.
func (r *PolicyRepository) RollbackToVersion(
	ctx context.Context,
	tenantID, policyID string,
	version int,
) (*domain.Policy, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once the tx has committed; nothing to report on the happy path

	target, err := scanPolicyVersion(tx.QueryRow(
		ctx,
		`SELECT pv.policy_id, pv.version, pv.upstream_id, pv.name, pv.type, pv.action, pv.schema_version, pv.config, pv.target, pv.priority, pv.enabled, pv.created_at
		 FROM policy_versions pv
		 JOIN policies p ON p.id = pv.policy_id
		 WHERE p.tenant_id = $1 AND pv.policy_id = $2 AND pv.version = $3`,
		tenantID,
		policyID,
		version,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if _, currentErr := r.GetByID(ctx, tenantID, policyID); currentErr != nil {
				return nil, currentErr
			}
			return nil, domain.ErrPolicyVersionNotFound
		}
		return nil, fmt.Errorf("loading policy version: %w", err)
	}

	policyDef := domain.Policy{
		ID:            policyID,
		TenantID:      tenantID,
		UpstreamID:    target.UpstreamID,
		Name:          target.Name,
		Type:          target.Type,
		Action:        target.Action,
		SchemaVersion: target.SchemaVersion,
		Config:        target.Config,
		Target:        target.Target,
		Priority:      target.Priority,
		Enabled:       target.Enabled,
	}
	if err := corepolicy.ValidatePolicy(policyDef); err != nil {
		return nil, err
	}

	configJSON, err := json.Marshal(target.Config)
	if err != nil {
		return nil, fmt.Errorf("marshalling rolled back config: %w", err)
	}
	targetJSON, err := json.Marshal(target.Target)
	if err != nil {
		return nil, fmt.Errorf("marshalling rolled back target: %w", err)
	}

	err = tx.QueryRow(ctx,
		`UPDATE policies
		 SET upstream_id = $1, name = $2, type = $3, action = $4, schema_version = $5, config = $6, target = $7, priority = $8,
		     enabled = $9, version = version + 1, updated_at = now()
		 WHERE tenant_id = $10 AND id = $11
		 RETURNING version, created_at, updated_at`,
		nullableString(target.UpstreamID),
		target.Name,
		target.Type,
		target.Action,
		target.SchemaVersion,
		configJSON,
		nullableJSON(targetJSON, target.Target != nil),
		target.Priority,
		target.Enabled,
		tenantID,
		policyID,
	).Scan(&policyDef.Version, &policyDef.CreatedAt, &policyDef.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("updating policy during rollback: %w", err)
	}

	_, err = tx.Exec(
		ctx,
		`INSERT INTO policy_versions (policy_id, version, upstream_id, name, type, action, schema_version, config, target, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		policyID,
		policyDef.Version,
		nullableString(policyDef.UpstreamID),
		policyDef.Name,
		policyDef.Type,
		policyDef.Action,
		policyDef.SchemaVersion,
		configJSON,
		nullableJSON(targetJSON, policyDef.Target != nil),
		policyDef.Priority,
		policyDef.Enabled,
	)
	if err != nil {
		return nil, fmt.Errorf("recording rollback policy version: %w", err)
	}
	if err := prunePolicyVersions(ctx, tx, policyID); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing policy rollback: %w", err)
	}

	return &policyDef, nil
}

func prunePolicyVersions(ctx context.Context, tx pgx.Tx, policyID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM policy_versions
		 WHERE id IN (
		 	SELECT id
		 	FROM policy_versions
		 	WHERE policy_id = $1
		 	ORDER BY version DESC
		 	OFFSET $2
		 )`,
		policyID, retainedPolicyVersionCount,
	)
	if err != nil {
		return fmt.Errorf("pruning retained policy versions: %w", err)
	}
	return nil
}
