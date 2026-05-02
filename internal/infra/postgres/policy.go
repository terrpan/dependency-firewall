package postgres

import (
	"context"
	"database/sql"
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
	var p domain.Policy
	var upstreamID sql.NullString
	var configJSON []byte
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, upstream_id, name, type, action, schema_version, config, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&p.ID, &p.TenantID, &upstreamID, &p.Name, &p.Type, &p.Action, &p.SchemaVersion, &configJSON,
		&p.Priority, &p.Enabled, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("querying policy by id: %w", err)
	}
	if upstreamID.Valid {
		p.UpstreamID = upstreamID.String
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
		`SELECT id, tenant_id, upstream_id, name, type, action, schema_version, config, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 ORDER BY priority`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	defer rows.Close()

	var policies []domain.Policy
	for rows.Next() {
		var p domain.Policy
		var upstreamID sql.NullString
		var configJSON []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &upstreamID, &p.Name, &p.Type, &p.Action, &p.SchemaVersion, &configJSON,
			&p.Priority, &p.Enabled, &p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning policy row: %w", err)
		}
		if upstreamID.Valid {
			p.UpstreamID = upstreamID.String
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
		`SELECT pv.policy_id, pv.version, pv.upstream_id, pv.name, pv.type, pv.action, pv.schema_version, pv.config, pv.priority, pv.enabled, pv.created_at
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
		`INSERT INTO policies (tenant_id, upstream_id, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, version, created_at, updated_at`,
		policy.TenantID, nullableString(policy.UpstreamID), policy.Name, policy.Type, policy.Action, policy.SchemaVersion,
		configJSON, policy.Priority, policy.Enabled,
	).Scan(&policy.ID, &policy.Version, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		if mappedErr := mapConstraintError(err, policyConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("inserting policy: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, version, upstream_id, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		policy.ID, policy.Version, nullableString(policy.UpstreamID), policy.Name, policy.Type, policy.Action, policy.SchemaVersion, configJSON, policy.Priority, policy.Enabled,
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
		 SET upstream_id = $1, name = $2, type = $3, action = $4, schema_version = $5, config = $6, priority = $7,
		     enabled = $8, version = version + 1, updated_at = now()
		 WHERE tenant_id = $9 AND id = $10
		 RETURNING version, updated_at`,
		nullableString(policy.UpstreamID), policy.Name, policy.Type, policy.Action, policy.SchemaVersion, configJSON,
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
		`INSERT INTO policy_versions (policy_id, version, upstream_id, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		policy.ID, newVersion, nullableString(policy.UpstreamID), policy.Name, policy.Type, policy.Action, policy.SchemaVersion, configJSON, policy.Priority, policy.Enabled,
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
	defer tx.Rollback(ctx) //nolint:errcheck

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

// RollbackToVersion restores a policy from a retained snapshot and creates a new current version.
func (r *PolicyRepository) RollbackToVersion(ctx context.Context, tenantID, policyID string, version int) (*domain.Policy, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var target domain.PolicyVersion
	var upstreamID sql.NullString
	var configJSON []byte
	err = tx.QueryRow(ctx,
		`SELECT pv.policy_id, pv.version, pv.upstream_id, pv.name, pv.type, pv.action, pv.schema_version, pv.config, pv.priority, pv.enabled, pv.created_at
		 FROM policy_versions pv
		 JOIN policies p ON p.id = pv.policy_id
		 WHERE p.tenant_id = $1 AND pv.policy_id = $2 AND pv.version = $3`,
		tenantID, policyID, version,
	).Scan(&target.PolicyID, &target.Version, &upstreamID, &target.Name, &target.Type, &target.Action, &target.SchemaVersion, &configJSON, &target.Priority, &target.Enabled, &target.CreatedAt)
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
	if upstreamID.Valid {
		target.UpstreamID = upstreamID.String
	}

	config, err := corepolicy.DecodeStoredConfigJSON(target.Type, target.SchemaVersion, configJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding policy version config: %w", err)
	}
	target.Config = config

	policyDef := domain.Policy{
		ID:            policyID,
		TenantID:      tenantID,
		UpstreamID:    target.UpstreamID,
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
		 SET upstream_id = $1, name = $2, type = $3, action = $4, schema_version = $5, config = $6, priority = $7,
		     enabled = $8, version = version + 1, updated_at = now()
		 WHERE tenant_id = $9 AND id = $10
		 RETURNING version, created_at, updated_at`,
		nullableString(target.UpstreamID), target.Name, target.Type, target.Action, target.SchemaVersion, configJSON, target.Priority, target.Enabled, tenantID, policyID,
	).Scan(&policyDef.Version, &policyDef.CreatedAt, &policyDef.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("updating policy during rollback: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, version, upstream_id, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		policyID, policyDef.Version, nullableString(policyDef.UpstreamID), policyDef.Name, policyDef.Type, policyDef.Action, policyDef.SchemaVersion, configJSON, policyDef.Priority, policyDef.Enabled,
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
	var upstreamID sql.NullString
	var configJSON []byte
	if err := row.Scan(&version.PolicyID, &version.Version, &upstreamID, &version.Name, &version.Type, &version.Action, &version.SchemaVersion, &configJSON, &version.Priority, &version.Enabled, &version.CreatedAt); err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("scanning policy version row: %w", err)
	}
	if upstreamID.Valid {
		version.UpstreamID = upstreamID.String
	}
	config, err := corepolicy.DecodeStoredConfigJSON(version.Type, version.SchemaVersion, configJSON)
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("decoding policy version config: %w", err)
	}
	version.Config = config
	return version, nil
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
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
