package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// PolicyRepository implements port.PolicyRepository using PostgreSQL.
type PolicyRepository struct {
	pool *pgxpool.Pool
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
		`SELECT id, tenant_id, name, type, action, config, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.Action, &configJSON,
		&p.Priority, &p.Enabled, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("querying policy by id: %w", err)
	}
	if err := json.Unmarshal(configJSON, &p.Config); err != nil {
		return nil, fmt.Errorf("unmarshalling policy config: %w", err)
	}
	return &p, nil
}

// ListByTenant returns all policies for a tenant, ordered by priority.
func (r *PolicyRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Policy, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, name, type, action, config, priority, enabled, version, created_at, updated_at
		 FROM policies WHERE tenant_id = $1 ORDER BY priority`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	defer rows.Close()

	var policies []domain.Policy
	for rows.Next() {
		var p domain.Policy
		var configJSON []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.Action, &configJSON,
			&p.Priority, &p.Enabled, &p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning policy row: %w", err)
		}
		if err := json.Unmarshal(configJSON, &p.Config); err != nil {
			return nil, fmt.Errorf("unmarshalling policy config: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating policy rows: %w", err)
	}
	return policies, nil
}

// Create inserts a new policy and its initial version.
func (r *PolicyRepository) Create(ctx context.Context, policy *domain.Policy) error {
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
		`INSERT INTO policies (tenant_id, name, type, action, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, version, created_at, updated_at`,
		policy.TenantID, policy.Name, policy.Type, policy.Action,
		configJSON, policy.Priority, policy.Enabled,
	).Scan(&policy.ID, &policy.Version, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("inserting policy: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, version, config) VALUES ($1, $2, $3)`,
		policy.ID, policy.Version, configJSON,
	)
	if err != nil {
		return fmt.Errorf("inserting initial policy version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing policy creation: %w", err)
	}
	return nil
}

// Update modifies an existing policy and records a new version.
func (r *PolicyRepository) Update(ctx context.Context, policy *domain.Policy) error {
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
		 SET name = $1, type = $2, action = $3, config = $4, priority = $5,
		     enabled = $6, version = version + 1, updated_at = now()
		 WHERE tenant_id = $7 AND id = $8
		 RETURNING version, updated_at`,
		policy.Name, policy.Type, policy.Action, configJSON,
		policy.Priority, policy.Enabled, policy.TenantID, policy.ID,
	).Scan(&newVersion, &policy.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrPolicyNotFound
		}
		return fmt.Errorf("updating policy: %w", err)
	}
	policy.Version = newVersion

	_, err = tx.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, version, config) VALUES ($1, $2, $3)`,
		policy.ID, newVersion, configJSON,
	)
	if err != nil {
		return fmt.Errorf("inserting policy version: %w", err)
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
