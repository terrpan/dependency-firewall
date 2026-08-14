package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	p, err := scanPolicy(r.pool.QueryRow(
		ctx,
		`SELECT id, tenant_id, upstream_id, name, type, action, schema_version, config, target, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 AND id = $2`,
		tenantID,
		id,
	))
	if err != nil {
		if errors.Is(err, errNoPolicyRow) {
			return nil, domain.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("querying policy by id: %w", err)
	}
	return p, nil
}

// ListByTenant returns all policies for a tenant, ordered by priority.
func (r *PolicyRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Policy, error) {
	rows, err := r.pool.Query(
		ctx,
		`SELECT id, tenant_id, upstream_id, name, type, action, schema_version, config, target, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 ORDER BY priority`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	defer rows.Close()

	policies := []domain.Policy{}
	for rows.Next() {
		policy, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating policy rows: %w", err)
	}
	return policies, nil
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
	targetJSON, err := json.Marshal(policy.Target)
	if err != nil {
		return fmt.Errorf("marshalling policy target: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once the tx has committed; nothing to report on the happy path

	err = tx.QueryRow(
		ctx,
		`INSERT INTO policies (tenant_id, upstream_id, name, type, action, schema_version, config, target, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, version, created_at, updated_at`,
		policy.TenantID,
		nullableString(policy.UpstreamID),
		policy.Name,
		policy.Type,
		policy.Action,
		policy.SchemaVersion,
		configJSON,
		nullableJSON(targetJSON, policy.Target != nil),
		policy.Priority,
		policy.Enabled,
	).Scan(&policy.ID, &policy.Version, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		if mappedErr := mapConstraintError(err, policyConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("inserting policy: %w", err)
	}

	_, err = tx.Exec(
		ctx,
		`INSERT INTO policy_versions (tenant_id, policy_id, version, upstream_id, name, type, action, schema_version, config, target, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		policy.TenantID,
		policy.ID,
		policy.Version,
		nullableString(policy.UpstreamID),
		policy.Name,
		policy.Type,
		policy.Action,
		policy.SchemaVersion,
		configJSON,
		nullableJSON(targetJSON, policy.Target != nil),
		policy.Priority,
		policy.Enabled,
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
	targetJSON, err := json.Marshal(policy.Target)
	if err != nil {
		return fmt.Errorf("marshalling policy target: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once the tx has committed; nothing to report on the happy path

	var newVersion int
	err = tx.QueryRow(ctx,
		`UPDATE policies
		 SET upstream_id = $1, name = $2, type = $3, action = $4, schema_version = $5, config = $6, target = $7, priority = $8,
		     enabled = $9, version = version + 1, updated_at = now()
		 WHERE tenant_id = $10 AND id = $11
		 RETURNING version, updated_at`,
		nullableString(policy.UpstreamID), policy.Name, policy.Type, policy.Action, policy.SchemaVersion, configJSON,
		nullableJSON(targetJSON, policy.Target != nil), policy.Priority, policy.Enabled, policy.TenantID, policy.ID,
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

	_, err = tx.Exec(
		ctx,
		`INSERT INTO policy_versions (tenant_id, policy_id, version, upstream_id, name, type, action, schema_version, config, target, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		policy.TenantID,
		policy.ID,
		newVersion,
		nullableString(policy.UpstreamID),
		policy.Name,
		policy.Type,
		policy.Action,
		policy.SchemaVersion,
		configJSON,
		nullableJSON(targetJSON, policy.Target != nil),
		policy.Priority,
		policy.Enabled,
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
func (r *PolicyRepository) Delete(ctx context.Context, tenantID, id string, force bool) error {
	if force {
		return r.forceDelete(ctx, tenantID, id)
	}

	ct, err := r.pool.Exec(ctx,
		`DELETE FROM policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return domain.ErrPolicyInUse
		}
		return fmt.Errorf("deleting policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrPolicyNotFound
	}
	return nil
}

func (r *PolicyRepository) forceDelete(ctx context.Context, tenantID, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning forced policy delete: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once the tx has committed; nothing to report on the happy path

	if _, err := tx.Exec(ctx,
		`UPDATE evaluations SET policy_id = NULL WHERE tenant_id = $1 AND policy_id = $2`,
		tenantID, id,
	); err != nil {
		return fmt.Errorf("clearing evaluation policy references: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE decisions SET policy_id = NULL WHERE tenant_id = $1 AND policy_id = $2`,
		tenantID, id,
	); err != nil {
		return fmt.Errorf("clearing decision policy references: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE evaluation_reasons er
		 SET policy_id = NULL
		 WHERE er.policy_id = $2
		   AND EXISTS (
		     SELECT 1
		     FROM evaluations e
		     WHERE e.id = er.evaluation_id
		       AND e.tenant_id = $1
		   )`,
		tenantID, id,
	); err != nil {
		return fmt.Errorf("clearing evaluation reason policy references: %w", err)
	}

	ct, err := tx.Exec(ctx,
		`DELETE FROM policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("force deleting policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrPolicyNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing forced policy delete: %w", err)
	}
	return nil
}
