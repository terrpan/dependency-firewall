package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DataPlaneCredentialRepository struct{ pool *pgxpool.Pool }

func NewDataPlaneCredentialRepository(pool *pgxpool.Pool) *DataPlaneCredentialRepository {
	return &DataPlaneCredentialRepository{pool: pool}
}

func (r *DataPlaneCredentialRepository) Create(ctx context.Context, c *domain.DataPlaneCredential) error {
	err := r.pool.QueryRow(ctx, `INSERT INTO data_plane_credentials
		(tenant_id, organization_id, team_id, name, secret_digest, expires_at, created_by)
		VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7)
		RETURNING id, created_at, updated_at`, c.TenantID, c.OrganizationID, c.TeamID, c.Name, c.SecretDigest, c.ExpiresAt, c.CreatedBy).
		Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if isConstraint(err, "data_plane_credentials_name_key") {
			return domain.ErrCredentialNameConflict
		}
		return fmt.Errorf("creating data-plane credential: %w", err)
	}
	return nil
}

func (r *DataPlaneCredentialRepository) GetByID(ctx context.Context, tenantID, id string) (*domain.DataPlaneCredential, error) {
	return scanCredential(r.pool.QueryRow(ctx, `SELECT id,tenant_id,organization_id,COALESCE(team_id::text,''),name,secret_digest,expires_at,revoked_at,created_by,last_used_at,created_at,updated_at FROM data_plane_credentials WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

func (r *DataPlaneCredentialRepository) ListByScope(ctx context.Context, tenantID, organizationID, teamID string) ([]domain.DataPlaneCredential, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,tenant_id,organization_id,COALESCE(team_id::text,''),name,secret_digest,expires_at,revoked_at,created_by,last_used_at,created_at,updated_at FROM data_plane_credentials WHERE tenant_id=$1 AND organization_id=$2 AND team_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid ORDER BY name`, tenantID, organizationID, teamID)
	if err != nil {
		return nil, fmt.Errorf("listing data-plane credentials: %w", err)
	}
	defer rows.Close()
	var out []domain.DataPlaneCredential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (r *DataPlaneCredentialRepository) ListVerifiersByTenant(ctx context.Context, tenantID string) ([]domain.DataPlaneCredentialVerifier, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,tenant_id,organization_id,COALESCE(team_id::text,''),secret_digest,expires_at,revoked_at FROM data_plane_credentials WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing credential verifiers: %w", err)
	}
	defer rows.Close()
	var out []domain.DataPlaneCredentialVerifier
	for rows.Next() {
		var v domain.DataPlaneCredentialVerifier
		if err := rows.Scan(&v.ID, &v.TenantID, &v.OrganizationID, &v.TeamID, &v.SecretDigest, &v.ExpiresAt, &v.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *DataPlaneCredentialRepository) Revoke(ctx context.Context, tenantID, id string, at time.Time) error {
	ct, err := r.pool.Exec(ctx, `UPDATE data_plane_credentials SET revoked_at=$1, updated_at=now() WHERE tenant_id=$2 AND id=$3`, at, tenantID, id)
	if err != nil {
		return fmt.Errorf("revoking data-plane credential: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrCredentialNotFound
	}
	return nil
}

type credentialRow interface{ Scan(...any) error }

func scanCredential(row credentialRow) (*domain.DataPlaneCredential, error) {
	var c domain.DataPlaneCredential
	err := row.Scan(&c.ID, &c.TenantID, &c.OrganizationID, &c.TeamID, &c.Name, &c.SecretDigest, &c.ExpiresAt, &c.RevokedAt, &c.CreatedBy, &c.LastUsedAt, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrCredentialNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scanning data-plane credential: %w", err)
	}
	return &c, nil
}
