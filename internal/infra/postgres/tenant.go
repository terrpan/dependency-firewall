package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// TenantRepository implements port.TenantRepository using PostgreSQL.
type TenantRepository struct {
	pool *pgxpool.Pool
}

var tenantConstraintErrors = map[string]error{
	"tenants_name_key": domain.ErrTenantNameConflict,
}

// NewTenantRepository creates a new TenantRepository.
func NewTenantRepository(pool *pgxpool.Pool) *TenantRepository {
	return &TenantRepository{pool: pool}
}

// GetByID returns a tenant by its ID.
func (r *TenantRepository) GetByID(ctx context.Context, id string) (*domain.Tenant, error) {
	var t domain.Tenant
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, created_at, updated_at FROM tenants WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrTenantNotFound
		}
		return nil, fmt.Errorf("querying tenant by id: %w", err)
	}
	return &t, nil
}

// List returns all tenants.
func (r *TenantRepository) List(ctx context.Context) ([]domain.Tenant, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, created_at, updated_at FROM tenants ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var tenants []domain.Tenant
	for rows.Next() {
		var t domain.Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning tenant row: %w", err)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating tenant rows: %w", err)
	}
	return tenants, nil
}

// Create inserts a new tenant and sets its generated ID.
func (r *TenantRepository) Create(ctx context.Context, tenant *domain.Tenant) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ($1)
		 RETURNING id, created_at, updated_at`,
		tenant.Name,
	).Scan(&tenant.ID, &tenant.CreatedAt, &tenant.UpdatedAt)
	if err != nil {
		if mappedErr := mapConstraintError(err, tenantConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("creating tenant: %w", err)
	}
	return nil
}

// Update modifies an existing tenant.
func (r *TenantRepository) Update(ctx context.Context, tenant *domain.Tenant) error {
	ct, err := r.pool.Exec(ctx,
		`UPDATE tenants SET name = $1, updated_at = now() WHERE id = $2`,
		tenant.Name, tenant.ID,
	)
	if err != nil {
		if mappedErr := mapConstraintError(err, tenantConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("updating tenant: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrTenantNotFound
	}
	return nil
}

// Delete removes a tenant by ID.
func (r *TenantRepository) Delete(ctx context.Context, id string) error {
	ct, err := r.pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting tenant: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrTenantNotFound
	}
	return nil
}
