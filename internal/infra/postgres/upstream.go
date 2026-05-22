package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// UpstreamRepository implements port.UpstreamRepository using PostgreSQL.
type UpstreamRepository struct {
	pool        *pgxpool.Pool
	secretCodec secretCodec
}

type secretCodec interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

var upstreamConstraintErrors = map[string]error{
	"upstreams_tenant_id_name_key":           domain.ErrUpstreamNameConflict,
	"uq_upstreams_tenant_ecosystem_base_url": domain.ErrUpstreamRegistryConflict,
}

// NewUpstreamRepository creates a new UpstreamRepository.
func NewUpstreamRepository(pool *pgxpool.Pool, codecs ...secretCodec) *UpstreamRepository {
	var codec secretCodec
	if len(codecs) > 0 {
		codec = codecs[0]
	}
	return &UpstreamRepository{pool: pool, secretCodec: codec}
}

// GetByID returns an upstream scoped to the given tenant.
func (r *UpstreamRepository) GetByID(ctx context.Context, tenantID, id string) (*domain.Upstream, error) {
	var u domain.Upstream
	var capabilities []string
	var authType string
	var authUsername sql.NullString
	var authSecret sql.NullString
	var authUpdatedAt sql.NullTime
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, ecosystem, base_url, capabilities,
		        auth_type, auth_username, auth_secret::text, auth_updated_at,
		        created_at, updated_at
		 FROM upstreams WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&u.ID, &u.TenantID, &u.Name, &u.Ecosystem, &u.BaseURL, &capabilities, &authType, &authUsername, &authSecret, &authUpdatedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUpstreamNotFound
		}
		return nil, fmt.Errorf("querying upstream by id: %w", err)
	}
	u.Capabilities = domain.ParseUpstreamCapabilities(capabilities)
	if err := r.attachAuth(&u, authType, authUsername, authSecret, authUpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetByEcosystem returns the active upstream for a tenant's ecosystem.
func (r *UpstreamRepository) GetByEcosystem(ctx context.Context, tenantID string, eco domain.EcosystemType) (*domain.Upstream, error) {
	var u domain.Upstream
	var capabilities []string
	var authType string
	var authUsername sql.NullString
	var authSecret sql.NullString
	var authUpdatedAt sql.NullTime
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, ecosystem, base_url, capabilities,
		        auth_type, auth_username, auth_secret::text, auth_updated_at,
		        created_at, updated_at
		 FROM upstreams
		 WHERE tenant_id = $1 AND ecosystem = $2
		 ORDER BY updated_at DESC, created_at DESC
		 LIMIT 1`, tenantID, string(eco),
	).Scan(&u.ID, &u.TenantID, &u.Name, &u.Ecosystem, &u.BaseURL, &capabilities, &authType, &authUsername, &authSecret, &authUpdatedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUpstreamNotFound
		}
		return nil, fmt.Errorf("querying upstream by ecosystem: %w", err)
	}
	u.Capabilities = domain.ParseUpstreamCapabilities(capabilities)
	if err := r.attachAuth(&u, authType, authUsername, authSecret, authUpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

// ListByTenant returns all upstreams for a tenant.
func (r *UpstreamRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, name, ecosystem, base_url, capabilities,
		        auth_type, auth_username, auth_secret::text, auth_updated_at,
		        created_at, updated_at
		 FROM upstreams WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing upstreams by tenant: %w", err)
	}
	defer rows.Close()

	var upstreams []domain.Upstream
	for rows.Next() {
		var u domain.Upstream
		var capabilities []string
		var authType string
		var authUsername sql.NullString
		var authSecret sql.NullString
		var authUpdatedAt sql.NullTime
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Name, &u.Ecosystem, &u.BaseURL, &capabilities, &authType, &authUsername, &authSecret, &authUpdatedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning upstream row: %w", err)
		}
		u.Capabilities = domain.ParseUpstreamCapabilities(capabilities)
		if err := r.attachAuth(&u, authType, authUsername, authSecret, authUpdatedAt); err != nil {
			return nil, err
		}
		upstreams = append(upstreams, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating upstream rows: %w", err)
	}
	return upstreams, nil
}

// ListBundleByTenant returns upstreams for bundle construction without
// decrypting auth secrets. Auth metadata is included so delivery adapters can
// decide whether a secret must be rewrapped for the bundle recipient.
func (r *UpstreamRepository) ListBundleByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, name, ecosystem, base_url, capabilities,
		        auth_type, auth_username, auth_updated_at,
		        created_at, updated_at
		 FROM upstreams WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing bundle upstreams by tenant: %w", err)
	}
	defer rows.Close()

	var upstreams []domain.Upstream
	for rows.Next() {
		var u domain.Upstream
		var capabilities []string
		var authType string
		var authUsername sql.NullString
		var authUpdatedAt sql.NullTime
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Name, &u.Ecosystem, &u.BaseURL, &capabilities, &authType, &authUsername, &authUpdatedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning bundle upstream row: %w", err)
		}
		u.Capabilities = domain.ParseUpstreamCapabilities(capabilities)
		attachBundleAuthMetadata(&u, authType, authUsername, authUpdatedAt)
		upstreams = append(upstreams, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating bundle upstream rows: %w", err)
	}
	return upstreams, nil
}

// Create inserts a new upstream and sets its generated ID.
func (r *UpstreamRepository) Create(ctx context.Context, upstream *domain.Upstream) error {
	authType, authUsername, authSecret, err := r.authColumns(upstream.Auth)
	if err != nil {
		return err
	}

	var authUpdatedAt sql.NullTime
	err = r.pool.QueryRow(ctx,
		`INSERT INTO upstreams (tenant_id, name, ecosystem, base_url, capabilities, auth_type, auth_username, auth_secret, auth_updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, CASE WHEN $6 = 'none' THEN NULL ELSE now() END)
		 RETURNING id, auth_updated_at, created_at, updated_at`,
		upstream.TenantID, upstream.Name, upstream.Ecosystem, upstream.BaseURL, domain.UpstreamCapabilityStrings(upstream.Capabilities), authType, authUsername, authSecret,
	).Scan(&upstream.ID, &authUpdatedAt, &upstream.CreatedAt, &upstream.UpdatedAt)
	if err != nil {
		if mappedErr := mapConstraintError(err, upstreamConstraintErrors); mappedErr != err {
			return mappedErr
		}
		return fmt.Errorf("creating upstream: %w", err)
	}
	if upstream.Auth != nil && authUpdatedAt.Valid {
		upstream.Auth.UpdatedAt = authUpdatedAt.Time
	}
	return nil
}

// Update modifies an existing upstream scoped to its tenant.
func (r *UpstreamRepository) Update(ctx context.Context, upstream *domain.Upstream) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting upstream update: %w", err)
	}
	defer tx.Rollback(ctx)

	ct, err := tx.Exec(ctx,
		`UPDATE upstreams SET name = $1, ecosystem = $2, base_url = $3, capabilities = $4, updated_at = now()
		 WHERE tenant_id = $5 AND id = $6`,
		upstream.Name, upstream.Ecosystem, upstream.BaseURL, domain.UpstreamCapabilityStrings(upstream.Capabilities),
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

	if upstream.Auth != nil {
		authType, authUsername, authSecret, err := r.authColumns(upstream.Auth)
		if err != nil {
			return err
		}
		var authUpdatedAt sql.NullTime
		err = tx.QueryRow(ctx,
			`UPDATE upstreams
			 SET auth_type = $1, auth_username = $2, auth_secret = $3::jsonb,
			     auth_updated_at = CASE WHEN $1 = 'none' THEN NULL ELSE now() END,
			     updated_at = now()
			 WHERE tenant_id = $4 AND id = $5
			 RETURNING auth_updated_at`,
			authType, authUsername, authSecret, upstream.TenantID, upstream.ID,
		).Scan(&authUpdatedAt)
		if err != nil {
			return fmt.Errorf("updating upstream auth: %w", err)
		}
		if authUpdatedAt.Valid {
			upstream.Auth.UpdatedAt = authUpdatedAt.Time
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing upstream update: %w", err)
	}
	return nil
}

// Delete removes an upstream scoped to the given tenant.
func (r *UpstreamRepository) Delete(ctx context.Context, tenantID, id string) error {
	ct, err := r.pool.Exec(ctx,
		`DELETE FROM upstreams WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" && pgErr.ConstraintName == "fk_policies_upstream_id" {
			return domain.ErrUpstreamInUse
		}
		return fmt.Errorf("deleting upstream: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrUpstreamNotFound
	}
	return nil
}

// RewrapUpstreamAuthSecret decrypts one stored secret and immediately passes
// the plaintext bytes to wrap. The plaintext buffer is cleared before returning.
func (r *UpstreamRepository) RewrapUpstreamAuthSecret(ctx context.Context, tenantID, upstreamID string, wrap port.UpstreamAuthSecretWrapper) ([]byte, error) {
	if wrap == nil {
		return nil, fmt.Errorf("upstream auth secret wrapper is not configured")
	}
	if r.secretCodec == nil {
		return nil, domain.ErrUpstreamAuthKeyUnavailable
	}

	var encryptedSecret sql.NullString
	err := r.pool.QueryRow(ctx,
		`SELECT auth_secret::text
		 FROM upstreams
		 WHERE tenant_id = $1
		   AND id = $2
		   AND auth_type <> 'none'`, tenantID, upstreamID,
	).Scan(&encryptedSecret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUpstreamNotFound
		}
		return nil, fmt.Errorf("querying upstream auth secret: %w", err)
	}
	if !encryptedSecret.Valid || encryptedSecret.String == "" {
		return nil, fmt.Errorf("%w: stored secret is empty", domain.ErrUpstreamAuthInvalid)
	}

	plaintext, err := r.secretCodec.Decrypt([]byte(encryptedSecret.String))
	if err != nil {
		return nil, fmt.Errorf("decrypting upstream auth for bundle: %w", err)
	}
	defer clearBytes(plaintext)

	rewrapped, err := wrap(plaintext)
	if err != nil {
		return nil, fmt.Errorf("rewrapping upstream auth for bundle: %w", err)
	}
	return rewrapped, nil
}

func (r *UpstreamRepository) authColumns(auth *domain.UpstreamAuth) (string, any, any, error) {
	if !auth.Configured() {
		return string(domain.UpstreamAuthNone), nil, nil, nil
	}
	if r.secretCodec == nil {
		return "", nil, nil, domain.ErrUpstreamAuthKeyUnavailable
	}
	encrypted, err := r.secretCodec.Encrypt([]byte(auth.Secret))
	if err != nil {
		return "", nil, nil, fmt.Errorf("encrypting upstream auth: %w", err)
	}

	var username any
	if auth.Type == domain.UpstreamAuthBasic {
		username = auth.Username
	}
	return string(auth.Type), username, string(encrypted), nil
}

func (r *UpstreamRepository) attachAuth(upstream *domain.Upstream, authType string, username, encryptedSecret sql.NullString, updatedAt sql.NullTime) error {
	if authType == "" || authType == string(domain.UpstreamAuthNone) {
		upstream.Auth = nil
		return nil
	}
	if r.secretCodec == nil {
		return domain.ErrUpstreamAuthKeyUnavailable
	}
	if !encryptedSecret.Valid || encryptedSecret.String == "" {
		return fmt.Errorf("%w: stored secret is empty", domain.ErrUpstreamAuthInvalid)
	}

	plaintext, err := r.secretCodec.Decrypt([]byte(encryptedSecret.String))
	if err != nil {
		return fmt.Errorf("decrypting upstream auth: %w", err)
	}

	auth := &domain.UpstreamAuth{
		Type:   domain.UpstreamAuthType(authType),
		Secret: string(plaintext),
	}
	if username.Valid {
		auth.Username = username.String
	}
	if updatedAt.Valid {
		auth.UpdatedAt = updatedAt.Time
	}
	upstream.Auth = auth
	return nil
}

func attachBundleAuthMetadata(upstream *domain.Upstream, authType string, username sql.NullString, updatedAt sql.NullTime) {
	if authType == "" || authType == string(domain.UpstreamAuthNone) {
		upstream.Auth = nil
		return
	}

	auth := &domain.UpstreamAuth{
		Type: domain.UpstreamAuthType(authType),
	}
	if username.Valid {
		auth.Username = username.String
	}
	if updatedAt.Valid {
		auth.UpdatedAt = updatedAt.Time
	}
	upstream.Auth = auth
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
