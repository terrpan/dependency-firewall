package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

const retainedPolicyVersionCount = domain.MaxRetainedPolicyVersions

// PolicyRepository implements port.PolicyRepository using PostgreSQL.
type PolicyRepository struct {
	pool *pgxpool.Pool
}

var policyConstraintErrors = map[string]error{
	"policies_tenant_id_name_key": domain.ErrPolicyNameConflict,
}

// NewPolicyRepository creates a new PolicyRepository.
func NewPolicyRepository(pool *pgxpool.Pool) *PolicyRepository {
	return &PolicyRepository{pool: pool}
}

// GetByID returns a policy scoped to the given tenant.
func (r *PolicyRepository) GetByID(ctx context.Context, tenantID, id string) (*domain.Policy, error) {
	var p domain.Policy
	var configJSON []byte
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, type, action, schema_version, config, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.Action, &p.SchemaVersion, &configJSON,
		&p.Priority, &p.Enabled, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("querying policy by id: %w", err)
	}
	config, err := corepolicy.DecodeStoredConfigJSON(p.Type, p.SchemaVersion, configJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding policy config: %w", err)
	}
	p.Config = config
	return &p, nil
}

// ListByTenant returns all policies for a tenant, ordered by priority.
func (r *PolicyRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Policy, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, name, type, action, schema_version, config, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 ORDER BY priority`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	defer rows.Close()

	var policies []domain.Policy
	for rows.Next() {
		var p domain.Policy
		var configJSON []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.Action, &p.SchemaVersion, &configJSON,
			&p.Priority, &p.Enabled, &p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning policy row: %w", err)
		}
		config, err := corepolicy.DecodeStoredConfigJSON(p.Type, p.SchemaVersion, configJSON)
		if err != nil {
			return nil, fmt.Errorf("decoding policy config: %w", err)
		}
		p.Config = config
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating policy rows: %w", err)
	}
	return policies, nil
}

// ListVersions returns retained versions for a policy, newest first.
func (r *PolicyRepository) ListVersions(ctx context.Context, tenantID, policyID string, limit int) ([]domain.PolicyVersion, error) {
	if limit <= 0 {
		limit = retainedPolicyVersionCount
	}

	rows, err := r.pool.Query(ctx,
		`SELECT pv.policy_id, pv.version, pv.name, pv.type, pv.action, pv.schema_version, pv.config, pv.priority, pv.enabled, pv.created_at
		 FROM policy_versions pv
		 JOIN policies p ON p.id = pv.policy_id
		 WHERE p.tenant_id = $1 AND pv.policy_id = $2
		 ORDER BY pv.version DESC
		 LIMIT $3`,
		tenantID, policyID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("listing policy versions: %w", err)
	}
	defer rows.Close()

	var versions []domain.PolicyVersion
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

// Create inserts a new policy and its initial version.
func (r *PolicyRepository) Create(ctx context.Context, policy *domain.Policy) error {
	if policy.SchemaVersion == 0 {
		normalizedSchemaVersion, err := corepolicy.NormalizeSchemaVersion(policy.Type, policy.SchemaVersion)
		if err != nil {
			return err
		}
		policy.SchemaVersion = normalizedSchemaVersion
	}
	if err := corepolicy.ValidatePolicy(*policy); err != nil {
		return err
	}
	configJSON, err := json.Marshal(policy.Config)
	if err != nil {
		return fmt.Errorf("marshalling policy config: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	err = tx.QueryRow(ctx,
		`INSERT INTO policies (tenant_id, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, version, created_at, updated_at`,
		policy.TenantID, policy.Name, policy.Type, policy.Action, policy.SchemaVersion,
		configJSON, policy.Priority, policy.Enabled,
	).Scan(&policy.ID, &policy.Version, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		if mappedErr := mapConstraintError(err, policyConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("inserting policy: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, version, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		policy.ID, policy.Version, policy.Name, policy.Type, policy.Action, policy.SchemaVersion, configJSON, policy.Priority, policy.Enabled,
	)
	if err != nil {
		return fmt.Errorf("inserting initial policy version: %w", err)
	}
	if err := prunePolicyVersions(ctx, tx, policy.ID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing policy creation: %w", err)
	}
	return nil
}

// Update modifies an existing policy and records a new version.
func (r *PolicyRepository) Update(ctx context.Context, policy *domain.Policy) error {
	if policy.SchemaVersion == 0 {
		normalizedSchemaVersion, err := corepolicy.NormalizeSchemaVersion(policy.Type, policy.SchemaVersion)
		if err != nil {
			return err
		}
		policy.SchemaVersion = normalizedSchemaVersion
	}
	if err := corepolicy.ValidatePolicy(*policy); err != nil {
		return err
	}
	configJSON, err := json.Marshal(policy.Config)
	if err != nil {
		return fmt.Errorf("marshalling policy config: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var newVersion int
	err = tx.QueryRow(ctx,
		`UPDATE policies
		 SET name = $1, type = $2, action = $3, schema_version = $4, config = $5, priority = $6,
		     enabled = $7, version = version + 1, updated_at = now()
		 WHERE tenant_id = $8 AND id = $9
		 RETURNING version, updated_at`,
		policy.Name, policy.Type, policy.Action, policy.SchemaVersion, configJSON,
		policy.Priority, policy.Enabled, policy.TenantID, policy.ID,
	).Scan(&newVersion, &policy.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrPolicyNotFound
		}
		if mappedErr := mapConstraintError(err, policyConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("updating policy: %w", err)
	}
	policy.Version = newVersion

	_, err = tx.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, version, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		policy.ID, newVersion, policy.Name, policy.Type, policy.Action, policy.SchemaVersion, configJSON, policy.Priority, policy.Enabled,
	)
	if err != nil {
		return fmt.Errorf("inserting policy version: %w", err)
	}
	if err := prunePolicyVersions(ctx, tx, policy.ID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing policy update: %w", err)
	}
	return nil
}

// Delete removes a policy scoped to the given tenant.
func (r *PolicyRepository) Delete(ctx context.Context, tenantID, id string) error {
	ct, err := r.pool.Exec(ctx,
		`DELETE FROM policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("deleting policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrPolicyNotFound
	}
	return nil
}

// RollbackToVersion restores a policy from a retained snapshot and creates a new current version.
func (r *PolicyRepository) RollbackToVersion(ctx context.Context, tenantID, policyID string, version int) (*domain.Policy, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var target domain.PolicyVersion
	var configJSON []byte
	err = tx.QueryRow(ctx,
		`SELECT pv.policy_id, pv.version, pv.name, pv.type, pv.action, pv.schema_version, pv.config, pv.priority, pv.enabled, pv.created_at
		 FROM policy_versions pv
		 JOIN policies p ON p.id = pv.policy_id
		 WHERE p.tenant_id = $1 AND pv.policy_id = $2 AND pv.version = $3`,
		tenantID, policyID, version,
	).Scan(&target.PolicyID, &target.Version, &target.Name, &target.Type, &target.Action, &target.SchemaVersion, &configJSON, &target.Priority, &target.Enabled, &target.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			current, currentErr := r.GetByID(ctx, tenantID, policyID)
			if currentErr != nil {
				return nil, currentErr
			}
			_ = current
			return nil, domain.ErrPolicyVersionNotFound
		}
		return nil, fmt.Errorf("loading policy version: %w", err)
	}

	config, err := corepolicy.DecodeStoredConfigJSON(target.Type, target.SchemaVersion, configJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding policy version config: %w", err)
	}
	target.Config = config

	policyDef := domain.Policy{
		ID:            policyID,
		TenantID:      tenantID,
		Name:          target.Name,
		Type:          target.Type,
		Action:        target.Action,
		SchemaVersion: target.SchemaVersion,
		Config:        target.Config,
		Priority:      target.Priority,
		Enabled:       target.Enabled,
	}
	if err := corepolicy.ValidatePolicy(policyDef); err != nil {
		return nil, err
	}

	configJSON, err = json.Marshal(target.Config)
	if err != nil {
		return nil, fmt.Errorf("marshalling rolled back config: %w", err)
	}

	err = tx.QueryRow(ctx,
		`UPDATE policies
		 SET name = $1, type = $2, action = $3, schema_version = $4, config = $5, priority = $6,
		     enabled = $7, version = version + 1, updated_at = now()
		 WHERE tenant_id = $8 AND id = $9
		 RETURNING version, created_at, updated_at`,
		target.Name, target.Type, target.Action, target.SchemaVersion, configJSON, target.Priority, target.Enabled, tenantID, policyID,
	).Scan(&policyDef.Version, &policyDef.CreatedAt, &policyDef.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("updating policy during rollback: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, version, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		policyID, policyDef.Version, policyDef.Name, policyDef.Type, policyDef.Action, policyDef.SchemaVersion, configJSON, policyDef.Priority, policyDef.Enabled,
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

func scanPolicyVersion(row interface {
	Scan(dest ...any) error
}) (domain.PolicyVersion, error) {
	var version domain.PolicyVersion
	var configJSON []byte
	if err := row.Scan(&version.PolicyID, &version.Version, &version.Name, &version.Type, &version.Action, &version.SchemaVersion, &configJSON, &version.Priority, &version.Enabled, &version.CreatedAt); err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("scanning policy version row: %w", err)
	}
	config, err := corepolicy.DecodeStoredConfigJSON(version.Type, version.SchemaVersion, configJSON)
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("decoding policy version config: %w", err)
	}
	version.Config = config
	return version, nil
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
