package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const sessionBootstrapAttempts = 3

// SessionBootstrapRepository owns the transaction that establishes all local
// state for a verified external session. Network calls must complete before it starts.
type SessionBootstrapRepository struct{ pool *pgxpool.Pool }

func NewSessionBootstrapRepository(pool *pgxpool.Pool) *SessionBootstrapRepository {
	return &SessionBootstrapRepository{pool: pool}
}

func (r *SessionBootstrapRepository) Bootstrap(ctx context.Context, request domain.SessionBootstrapRequest) (*domain.SessionBootstrapResult, error) {
	var lastErr error
	for attempt := 0; attempt < sessionBootstrapAttempts; attempt++ {
		result, err := r.bootstrapOnce(ctx, request)
		if err == nil {
			return result, nil
		}
		if !retryableBootstrapConflict(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%w: concurrent identity provisioning did not converge: %v", domain.ErrSessionBootstrapConflict, lastErr)
}

func (r *SessionBootstrapRepository) bootstrapOnce(ctx context.Context, request domain.SessionBootstrapRequest) (*domain.SessionBootstrapResult, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting session bootstrap transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- commit or caller error is authoritative

	tenant, tenantCreated, err := bootstrapTenant(ctx, tx, request)
	if err != nil {
		return nil, err
	}
	principal, principalCreated, err := bootstrapPrincipal(ctx, tx, request)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing session bootstrap: %w", err)
	}
	return &domain.SessionBootstrapResult{
		Tenant: *tenant, Principal: *principal, Created: tenantCreated || principalCreated,
	}, nil
}

func bootstrapTenant(ctx context.Context, tx pgx.Tx, request domain.SessionBootstrapRequest) (*domain.Tenant, bool, error) {
	var tenant domain.Tenant
	err := tx.QueryRow(ctx,
		`SELECT t.id, t.name, t.created_at, t.updated_at
		 FROM tenants t
		 JOIN tenant_identity_links l ON l.tenant_id = t.id
		 WHERE l.provider = $1 AND l.external_id = $2`,
		request.Provider, request.ExternalAccountID,
	).Scan(&tenant.ID, &tenant.Name, &tenant.CreatedAt, &tenant.UpdatedAt)
	if err == nil {
		return &tenant, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("resolving bootstrap tenant: %w", err)
	}

	name := strings.TrimSpace(request.AccountName)
	if name == "" {
		name = "Account"
	}
	var nameExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1)`, name).Scan(&nameExists); err != nil {
		return nil, false, fmt.Errorf("checking bootstrap tenant name: %w", err)
	}
	if nameExists {
		name += " [" + stableExternalSuffix(request.ExternalAccountID) + "]"
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ($1)
		 RETURNING id, name, created_at, updated_at`, name,
	).Scan(&tenant.ID, &tenant.Name, &tenant.CreatedAt, &tenant.UpdatedAt); err != nil {
		return nil, false, fmt.Errorf("creating bootstrap tenant: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tenant_identity_links (tenant_id, provider, external_id)
		 VALUES ($1, $2, $3)`, tenant.ID, request.Provider, request.ExternalAccountID,
	); err != nil {
		return nil, false, fmt.Errorf("linking bootstrap tenant identity: %w", err)
	}
	return &tenant, true, nil
}

func bootstrapPrincipal(ctx context.Context, tx pgx.Tx, request domain.SessionBootstrapRequest) (*domain.Principal, bool, error) {
	var principal domain.Principal
	err := tx.QueryRow(ctx,
		`SELECT p.id, p.display_name, p.email, p.status, p.created_at, p.updated_at
		 FROM principals p
		 JOIN principal_identities i ON i.principal_id = p.id
		 WHERE i.provider = $1 AND i.external_subject = $2`,
		request.Provider, request.ExternalSubject,
	).Scan(
		&principal.ID, &principal.DisplayName, &principal.Email, &principal.Status,
		&principal.CreatedAt, &principal.UpdatedAt,
	)
	if err == nil {
		err = tx.QueryRow(ctx,
			`UPDATE principals
			 SET display_name = $1, email = $2, status = 'active', updated_at = now()
			 WHERE id = $3
			 RETURNING display_name, email, status, updated_at`,
			request.DisplayName, request.Email, principal.ID,
		).Scan(&principal.DisplayName, &principal.Email, &principal.Status, &principal.UpdatedAt)
		if err != nil {
			return nil, false, fmt.Errorf("refreshing bootstrap principal: %w", err)
		}
		return &principal, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("resolving bootstrap principal: %w", err)
	}

	err = tx.QueryRow(ctx,
		`INSERT INTO principals (display_name, email, status)
		 VALUES ($1, $2, 'active')
		 RETURNING id, display_name, email, status, created_at, updated_at`,
		request.DisplayName, request.Email,
	).Scan(
		&principal.ID, &principal.DisplayName, &principal.Email, &principal.Status,
		&principal.CreatedAt, &principal.UpdatedAt,
	)
	if err != nil {
		return nil, false, fmt.Errorf("creating bootstrap principal: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO principal_identities (principal_id, provider, external_subject)
		 VALUES ($1, $2, $3)`, principal.ID, request.Provider, request.ExternalSubject,
	); err != nil {
		return nil, false, fmt.Errorf("linking bootstrap principal identity: %w", err)
	}
	return &principal, true, nil
}

func retryableBootstrapConflict(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	switch pgErr.ConstraintName {
	case "tenants_name_key", "tenant_identity_links_provider_external_key", "principal_identities_pkey":
		return true
	default:
		return false
	}
}

func stableExternalSuffix(externalID string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(externalID)))
	return fmt.Sprintf("%x", digest[:4])
}
