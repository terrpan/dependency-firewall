package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// PolicyRevisionRepository implements port.PolicyRevisionRepository using PostgreSQL.
type PolicyRevisionRepository struct {
	pool *pgxpool.Pool
}

// NewPolicyRevisionRepository creates a new PolicyRevisionRepository.
func NewPolicyRevisionRepository(pool *pgxpool.Pool) *PolicyRevisionRepository {
	return &PolicyRevisionRepository{pool: pool}
}

// Create inserts the next tenant policy-set revision.
func (r *PolicyRevisionRepository) Create(ctx context.Context, revision *domain.PolicySetRevision) error {
	err := r.pool.QueryRow(ctx,
		`WITH next_generation AS (
			SELECT COALESCE(MAX(generation), 0) + 1 AS generation
			FROM tenant_policy_revisions
			WHERE tenant_id = $1
		)
		INSERT INTO tenant_policy_revisions (tenant_id, generation, policy_hash)
		SELECT $1, generation, $2
		FROM next_generation
		RETURNING id, generation, created_at`,
		revision.TenantID, revision.PolicyHash,
	).Scan(&revision.ID, &revision.Generation, &revision.CreatedAt)
	if err != nil {
		return fmt.Errorf("inserting tenant policy revision: %w", err)
	}
	return nil
}
