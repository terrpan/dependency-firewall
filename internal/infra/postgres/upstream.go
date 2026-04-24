package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// UpstreamRepository implements port.UpstreamRepository using PostgreSQL.
type UpstreamRepository struct {
	pool *pgxpool.Pool
}

var upstreamConstraintErrors = map[string]error{
	"upstreams_tenant_id_name_key":  domain.ErrUpstreamNameConflict,
	"uq_upstreams_tenant_ecosystem": domain.ErrUpstreamScopeConflict,
}

// NewUpstreamRepository creates a new UpstreamRepository.
func NewUpstreamRepository(pool *pgxpool.Pool) *UpstreamRepository {
	return &UpstreamRepository{pool: pool}
}

// GetByID returns an upstream scoped to the given tenant.
func (r *UpstreamRepository) GetByID(ctx context.Context, tenantID, id string) (*domain.Upstream, error) {
	var u domain.Upstream
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, ecosystem, base_url, created_at, updated_at
		 FROM upstreams WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&u.ID, &u.TenantID, &u.Name, &u.Ecosystem, &u.BaseURL, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUpstreamNotFound
		}
		return nil, fmt.Errorf("querying upstream by id: %w", err)
	}
	return &u, nil
}

// GetByEcosystem returns the upstream for a tenant's ecosystem.
func (r *UpstreamRepository) GetByEcosystem(ctx context.Context, tenantID string, eco domain.EcosystemType) (*domain.Upstream, error) {
	var u domain.Upstream
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, ecosystem, base_url, created_at, updated_at
		 FROM upstreams WHERE tenant_id = $1 AND ecosystem = $2`, tenantID, string(eco),
	).Scan(&u.ID, &u.TenantID, &u.Name, &u.Ecosystem, &u.BaseURL, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUpstreamNotFound
		}
		return nil, fmt.Errorf("querying upstream by ecosystem: %w", err)
	}
	return &u, nil
}

// ListByTenant returns all upstreams for a tenant.
func (r *UpstreamRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, name, ecosystem, base_url, created_at, updated_at
		 FROM upstreams WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing upstreams by tenant: %w", err)
	}
	defer rows.Close()

	var upstreams []domain.Upstream
	for rows.Next() {
		var u domain.Upstream
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Name, &u.Ecosystem, &u.BaseURL, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning upstream row: %w", err)
		}
		upstreams = append(upstreams, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating upstream rows: %w", err)
	}
	return upstreams, nil
}

// Create inserts a new upstream and sets its generated ID.
func (r *UpstreamRepository) Create(ctx context.Context, upstream *domain.Upstream) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO upstreams (tenant_id, name, ecosystem, base_url)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at, updated_at`,
		upstream.TenantID, upstream.Name, upstream.Ecosystem, upstream.BaseURL,
	).Scan(&upstream.ID, &upstream.CreatedAt, &upstream.UpdatedAt)
	if err != nil {
		if mappedErr := mapConstraintError(err, upstreamConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("creating upstream: %w", err)
	}
	return nil
}

// Update modifies an existing upstream scoped to its tenant.
func (r *UpstreamRepository) Update(ctx context.Context, upstream *domain.Upstream) error {
	ct, err := r.pool.Exec(ctx,
		`UPDATE upstreams SET name = $1, ecosystem = $2, base_url = $3, updated_at = now()
		 WHERE tenant_id = $4 AND id = $5`,
		upstream.Name, upstream.Ecosystem, upstream.BaseURL,
		upstream.TenantID, upstream.ID,
	)
	if err != nil {
		if mappedErr := mapConstraintError(err, upstreamConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("updating upstream: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrUpstreamNotFound
	}
	return nil
}

// Delete removes an upstream scoped to the given tenant.
func (r *UpstreamRepository) Delete(ctx context.Context, tenantID, id string) error {
	ct, err := r.pool.Exec(ctx,
		`DELETE FROM upstreams WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("deleting upstream: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrUpstreamNotFound
	}
	return nil
}
