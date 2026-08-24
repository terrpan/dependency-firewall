package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// ProxyEnrollmentRepository persists proxy installations, enrollments and workload identities.
type ProxyEnrollmentRepository struct {
	pool *pgxpool.Pool
}

// NewProxyEnrollmentRepository creates a PostgreSQL enrollment repository.
func NewProxyEnrollmentRepository(pool *pgxpool.Pool) *ProxyEnrollmentRepository {
	return &ProxyEnrollmentRepository{pool: pool}
}

// CreateProxyEnrollment inserts a digest-only pending enrollment.
func (r *ProxyEnrollmentRepository) CreateProxyEnrollment(
	ctx context.Context,
	enrollment *domain.ProxyEnrollment,
) error {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO proxy_enrollments (
			device_credential_digest, user_code_digest, csr_der, proposed_name, status,
			expires_at, poll_interval_seconds, next_poll_at
		) VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`,
		enrollment.DeviceCredentialDigest,
		enrollment.UserCodeDigest,
		enrollment.CSRDER,
		enrollment.ProposedName,
		enrollment.Status,
		enrollment.ExpiresAt,
		int64(enrollment.PollInterval/time.Second),
		enrollment.NextPollAt,
	).Scan(&enrollment.ID, &enrollment.CreatedAt, &enrollment.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating proxy enrollment: %w", err)
	}
	return nil
}

// ResolveProxyEnrollment locks and returns a pending enrollment by ID and user-code digest.
func (r *ProxyEnrollmentRepository) ResolveProxyEnrollment(
	ctx context.Context,
	enrollmentID string,
	userCodeDigest []byte,
	now time.Time,
) (*domain.ProxyEnrollment, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning proxy enrollment resolve: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	enrollment, err := selectEnrollmentForUpdate(ctx, tx,
		`WHERE id = $1 AND user_code_digest = $2`, enrollmentID, userCodeDigest)
	if err != nil {
		return nil, err
	}
	if err := expireEnrollmentIfNeeded(ctx, tx, enrollment, now); err != nil {
		return nil, err
	}
	if enrollment.Status != domain.ProxyEnrollmentPending {
		return nil, enrollmentStateError(enrollment.Status)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing proxy enrollment resolve: %w", err)
	}
	return enrollment, nil
}

// ResolveProxyEnrollmentByUserCode locks and safely resolves a globally unique code digest.
func (r *ProxyEnrollmentRepository) ResolveProxyEnrollmentByUserCode(
	ctx context.Context,
	userCodeDigest []byte,
	now time.Time,
) (*domain.ProxyEnrollment, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning proxy enrollment code resolve: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	enrollment, err := selectEnrollmentForUpdate(ctx, tx, `WHERE user_code_digest = $1`, userCodeDigest)
	if err != nil {
		return nil, err
	}
	if err := expireEnrollmentIfNeeded(ctx, tx, enrollment, now); err != nil {
		return nil, err
	}
	if enrollment.Status != domain.ProxyEnrollmentPending {
		return nil, enrollmentStateError(enrollment.Status)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing proxy enrollment code resolve: %w", err)
	}
	return enrollment, nil
}

// ApproveProxyEnrollment atomically creates identity state and commits the winning approval.
func (r *ProxyEnrollmentRepository) ApproveProxyEnrollment(
	ctx context.Context,
	enrollmentID string,
	userCodeDigest []byte,
	approval domain.ProxyEnrollmentApproval,
	now time.Time,
) (*domain.ProxyEnrollment, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning proxy enrollment approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	enrollment, err := selectEnrollmentForUpdate(ctx, tx,
		`WHERE id = $1 AND user_code_digest = $2`, enrollmentID, userCodeDigest)
	if err != nil {
		return nil, err
	}
	if err := expireEnrollmentIfNeeded(ctx, tx, enrollment, now); err != nil {
		return nil, err
	}
	if enrollment.Status != domain.ProxyEnrollmentPending {
		return nil, enrollmentStateError(enrollment.Status)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO proxy_installations (id, tenant_id, name, status)
		VALUES ($1, $2, $3, 'pending')`, approval.InstallationID, approval.TenantID, approval.InstallationName)
	if err != nil {
		return nil, mapProxyEnrollmentWriteError("creating proxy installation", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO workload_identities (
			id, tenant_id, installation_id, canonical_identity, certificate_serial, certificate_not_after
		) VALUES ($1, $2, $3, $4, $5, $6)`,
		approval.IdentityID,
		approval.TenantID,
		approval.InstallationID,
		approval.CanonicalIdentity,
		approval.CertificateSerial,
		approval.CertificateNotAfter,
	)
	if err != nil {
		return nil, mapProxyEnrollmentWriteError("creating workload identity", err)
	}
	ct, err := tx.Exec(ctx, `
		UPDATE proxy_enrollments SET
			status = 'approved', tenant_id = $1, installation_id = $2, identity_id = $3,
			canonical_identity = $4, certificate_chain_pem = $5, server_trust_bundle_pem = $6,
			approving_principal_id = $7, approved_at = $8, updated_at = $8
		WHERE id = $9 AND status = 'pending'`,
		approval.TenantID,
		approval.InstallationID,
		approval.IdentityID,
		approval.CanonicalIdentity,
		approval.CertificateChainPEM,
		approval.ServerTrustBundlePEM,
		approval.PrincipalID,
		now,
		enrollmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("approving proxy enrollment: %w", err)
	}
	if ct.RowsAffected() != 1 {
		return nil, domain.ErrProxyEnrollmentConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing proxy enrollment approval: %w", err)
	}
	enrollment.Status = domain.ProxyEnrollmentApproved
	enrollment.TenantID = approval.TenantID
	enrollment.InstallationID = approval.InstallationID
	enrollment.IdentityID = approval.IdentityID
	enrollment.CanonicalIdentity = approval.CanonicalIdentity
	enrollment.ApprovingPrincipalID = approval.PrincipalID
	enrollment.ApprovedAt = &now
	return enrollment, nil
}

// DenyProxyEnrollment atomically rejects a pending enrollment.
func (r *ProxyEnrollmentRepository) DenyProxyEnrollment(
	ctx context.Context,
	enrollmentID string,
	userCodeDigest []byte,
	principalID string,
	now time.Time,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning proxy enrollment denial: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	enrollment, err := selectEnrollmentForUpdate(ctx, tx,
		`WHERE id = $1 AND user_code_digest = $2`, enrollmentID, userCodeDigest)
	if err != nil {
		return err
	}
	if err := expireEnrollmentIfNeeded(ctx, tx, enrollment, now); err != nil {
		return err
	}
	if enrollment.Status != domain.ProxyEnrollmentPending {
		return enrollmentStateError(enrollment.Status)
	}
	_, err = tx.Exec(ctx, `
		UPDATE proxy_enrollments SET status = 'denied', denying_principal_id = $1,
			denied_at = $2, updated_at = $2 WHERE id = $3`, principalID, now, enrollmentID)
	if err != nil {
		return fmt.Errorf("denying proxy enrollment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing proxy enrollment denial: %w", err)
	}
	return nil
}

// PollProxyEnrollment enforces cadence and consumes approved certificate material exactly once.
//
//nolint:gocognit,funlen // the explicit branches are the persisted enrollment state machine.
func (r *ProxyEnrollmentRepository) PollProxyEnrollment(
	ctx context.Context,
	deviceCredentialDigest []byte,
	now time.Time,
) (*domain.ProxyEnrollment, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning proxy enrollment poll: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	enrollment, err := selectEnrollmentForUpdate(ctx, tx,
		`WHERE device_credential_digest = $1`, deviceCredentialDigest)
	if err != nil {
		return nil, err
	}
	if err := expireEnrollmentIfNeeded(ctx, tx, enrollment, now); err != nil {
		return nil, err
	}
	switch enrollment.Status {
	case domain.ProxyEnrollmentPending:
		if now.Before(enrollment.NextPollAt) {
			_, updateErr := tx.Exec(ctx, `UPDATE proxy_enrollments
				SET next_poll_at = next_poll_at + make_interval(secs => poll_interval_seconds), updated_at = $1
				WHERE id = $2`, now, enrollment.ID)
			if updateErr != nil {
				return nil, fmt.Errorf("delaying fast proxy enrollment poll: %w", updateErr)
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, fmt.Errorf("committing proxy enrollment slowdown: %w", err)
			}
			return nil, domain.ErrProxyEnrollmentSlowDown
		}
		_, err = tx.Exec(ctx, `UPDATE proxy_enrollments SET next_poll_at = $1, updated_at = $2 WHERE id = $3`,
			now.Add(enrollment.PollInterval), now, enrollment.ID)
		if err != nil {
			return nil, fmt.Errorf("scheduling next proxy enrollment poll: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("committing pending proxy enrollment poll: %w", err)
		}
		return nil, domain.ErrProxyEnrollmentPending
	case domain.ProxyEnrollmentApproved:
		_, err = tx.Exec(ctx, `UPDATE proxy_installations
			SET status = 'active', updated_at = $1 WHERE id = $2 AND tenant_id = $3 AND status = 'pending'`,
			now, enrollment.InstallationID, enrollment.TenantID)
		if err != nil {
			return nil, fmt.Errorf("activating proxy installation: %w", err)
		}
		ct, err := tx.Exec(ctx, `UPDATE proxy_enrollments SET status = 'consumed', consumed_at = $1,
			updated_at = $1, certificate_chain_pem = NULL, server_trust_bundle_pem = NULL
			WHERE id = $2 AND status = 'approved'`, now, enrollment.ID)
		if err != nil {
			return nil, fmt.Errorf("consuming proxy enrollment: %w", err)
		}
		if ct.RowsAffected() != 1 {
			return nil, domain.ErrProxyEnrollmentConsumed
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("committing proxy enrollment consumption: %w", err)
		}
		enrollment.Status = domain.ProxyEnrollmentConsumed
		enrollment.ConsumedAt = &now
		return enrollment, nil
	default:
		return nil, enrollmentStateError(enrollment.Status)
	}
}

// GetProxyInstallation returns one installation using both Tenant and installation predicates.
func (r *ProxyEnrollmentRepository) GetProxyInstallation(
	ctx context.Context,
	tenantID, id string,
) (*domain.ProxyInstallation, error) {
	row := r.pool.QueryRow(ctx, proxyInstallationSelect+` WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return scanProxyInstallation(row)
}

// ListProxyInstallations lists one Tenant's installations.
func (r *ProxyEnrollmentRepository) ListProxyInstallations(
	ctx context.Context,
	tenantID string,
) ([]domain.ProxyInstallation, error) {
	rows, err := r.pool.Query(ctx, proxyInstallationSelect+` WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing proxy installations: %w", err)
	}
	defer rows.Close()
	result := make([]domain.ProxyInstallation, 0)
	for rows.Next() {
		installation, err := scanProxyInstallation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *installation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating proxy installations: %w", err)
	}
	return result, nil
}

// RenameProxyInstallation renames a live Tenant-owned installation.
func (r *ProxyEnrollmentRepository) RenameProxyInstallation(
	ctx context.Context,
	tenantID, id, name string,
) (*domain.ProxyInstallation, error) {
	row := r.pool.QueryRow(ctx, `UPDATE proxy_installations SET name = $1, updated_at = now()
		WHERE tenant_id = $2 AND id = $3 AND status <> 'revoked'
		RETURNING id, tenant_id, name, status, created_at, updated_at, first_connected_at, revoked_at`, name, tenantID, id)
	installation, err := scanProxyInstallation(row)
	if err != nil {
		return nil, mapProxyEnrollmentWriteError("renaming proxy installation", err)
	}
	return installation, nil
}

// RevokeProxyInstallation atomically revokes an installation and its identities.
func (r *ProxyEnrollmentRepository) RevokeProxyInstallation(
	ctx context.Context,
	tenantID, id string,
	now time.Time,
) (*domain.ProxyInstallation, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning proxy installation revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	row := tx.QueryRow(ctx, `UPDATE proxy_installations SET status = 'revoked', revoked_at = $1, updated_at = $1
		WHERE tenant_id = $2 AND id = $3 AND status IN ('pending', 'active')
		RETURNING id, tenant_id, name, status, created_at, updated_at, first_connected_at, revoked_at`, now, tenantID, id)
	installation, err := scanProxyInstallation(row)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE workload_identities SET revoked_at = $1, updated_at = $1
		WHERE tenant_id = $2 AND installation_id = $3 AND revoked_at IS NULL`, now, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("revoking workload identities: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing proxy installation revocation: %w", err)
	}
	return installation, nil
}

// AuthorizeWorkloadIdentity checks current installation, identity, Tenant, and expiry state.
func (r *ProxyEnrollmentRepository) AuthorizeWorkloadIdentity(
	ctx context.Context,
	identities []string,
	tenantID string,
	now time.Time,
) (domain.WorkloadAuthorizationResult, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT wi.canonical_identity, wi.tenant_id, wi.installation_id,
			wi.revoked_at, wi.certificate_not_after, pi.status, pi.revoked_at, pi.first_connected_at
		FROM workload_identities wi
		JOIN proxy_installations pi ON pi.id = wi.installation_id AND pi.tenant_id = wi.tenant_id
		WHERE wi.canonical_identity = ANY($1::text[])`, identities)
	if err != nil {
		return domain.WorkloadAuthorizationResult{}, fmt.Errorf("querying workload identities: %w", err)
	}
	defer rows.Close()
	result := domain.WorkloadAuthorizationResult{}
	for rows.Next() {
		var identity, identityTenantID, installationID string
		var identityRevokedAt, installationRevokedAt, firstConnectedAt *time.Time
		var certificateNotAfter time.Time
		var status domain.ProxyInstallationStatus
		if err := rows.Scan(&identity, &identityTenantID, &installationID, &identityRevokedAt,
			&certificateNotAfter, &status, &installationRevokedAt, &firstConnectedAt); err != nil {
			return domain.WorkloadAuthorizationResult{}, fmt.Errorf("scanning workload identity: %w", err)
		}
		result.Known = true
		if identityTenantID == tenantID && identityRevokedAt == nil && installationRevokedAt == nil &&
			status == domain.ProxyInstallationActive && certificateNotAfter.After(now) {
			result.Authorized = true
			result.InstallationID = installationID
			result.FirstConnectedAt = firstConnectedAt
		}
	}
	if err := rows.Err(); err != nil {
		return domain.WorkloadAuthorizationResult{}, fmt.Errorf("iterating workload identities: %w", err)
	}
	if result.Authorized && result.FirstConnectedAt == nil {
		var connectedAt time.Time
		err := r.pool.QueryRow(ctx, `UPDATE proxy_installations SET first_connected_at = COALESCE(first_connected_at, $1),
			updated_at = CASE WHEN first_connected_at IS NULL THEN $1 ELSE updated_at END
			WHERE tenant_id = $2 AND id = $3 RETURNING first_connected_at`, now, tenantID, result.InstallationID).
			Scan(&connectedAt)
		if err != nil {
			return domain.WorkloadAuthorizationResult{}, fmt.Errorf("recording proxy first connection: %w", err)
		}
		result.FirstConnectedAt = &connectedAt
	}
	return result, nil
}

const proxyInstallationSelect = `SELECT id, tenant_id, name, status, created_at, updated_at, first_connected_at, revoked_at FROM proxy_installations`

func scanProxyInstallation(row rowScanner) (*domain.ProxyInstallation, error) {
	var installation domain.ProxyInstallation
	err := row.Scan(&installation.ID, &installation.TenantID, &installation.Name, &installation.Status,
		&installation.CreatedAt, &installation.UpdatedAt, &installation.FirstConnectedAt, &installation.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrProxyInstallationNotFound
		}
		return nil, fmt.Errorf("scanning proxy installation: %w", err)
	}
	return &installation, nil
}

func selectEnrollmentForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	where string,
	args ...any,
) (*domain.ProxyEnrollment, error) {
	query := `SELECT id, device_credential_digest, user_code_digest, csr_der, COALESCE(proposed_name, ''), status,
		expires_at, poll_interval_seconds, next_poll_at, COALESCE(tenant_id::text, ''),
		COALESCE(installation_id::text, ''), COALESCE(identity_id::text, ''), COALESCE(canonical_identity, ''),
		COALESCE(certificate_chain_pem, ''::bytea), COALESCE(server_trust_bundle_pem, ''::bytea),
		COALESCE(approving_principal_id, ''), COALESCE(denying_principal_id, ''), created_at, updated_at,
		approved_at, denied_at, consumed_at, expired_at
		FROM proxy_enrollments ` + where + ` FOR UPDATE`
	var enrollment domain.ProxyEnrollment
	var pollIntervalSeconds int64
	err := tx.QueryRow(ctx, query, args...).Scan(
		&enrollment.ID, &enrollment.DeviceCredentialDigest, &enrollment.UserCodeDigest, &enrollment.CSRDER,
		&enrollment.ProposedName, &enrollment.Status, &enrollment.ExpiresAt, &pollIntervalSeconds,
		&enrollment.NextPollAt, &enrollment.TenantID, &enrollment.InstallationID, &enrollment.IdentityID,
		&enrollment.CanonicalIdentity, &enrollment.CertificateChainPEM, &enrollment.ServerTrustBundlePEM,
		&enrollment.ApprovingPrincipalID, &enrollment.DenyingPrincipalID, &enrollment.CreatedAt,
		&enrollment.UpdatedAt, &enrollment.ApprovedAt, &enrollment.DeniedAt, &enrollment.ConsumedAt,
		&enrollment.ExpiredAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrProxyEnrollmentNotFound
		}
		return nil, fmt.Errorf("querying proxy enrollment: %w", err)
	}
	enrollment.PollInterval = time.Duration(pollIntervalSeconds) * time.Second
	return &enrollment, nil
}

func expireEnrollmentIfNeeded(ctx context.Context, tx pgx.Tx, enrollment *domain.ProxyEnrollment, now time.Time) error {
	if now.Before(enrollment.ExpiresAt) ||
		(enrollment.Status != domain.ProxyEnrollmentPending && enrollment.Status != domain.ProxyEnrollmentApproved) {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE proxy_enrollments SET status = 'expired', expired_at = $1,
		updated_at = $1, certificate_chain_pem = NULL, server_trust_bundle_pem = NULL
		WHERE id = $2 AND status IN ('pending', 'approved')`, now, enrollment.ID)
	if err != nil {
		return fmt.Errorf("expiring proxy enrollment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing proxy enrollment expiry: %w", err)
	}
	return domain.ErrProxyEnrollmentExpired
}

func enrollmentStateError(status domain.ProxyEnrollmentStatus) error {
	switch status {
	case domain.ProxyEnrollmentPending:
		return domain.ErrProxyEnrollmentPending
	case domain.ProxyEnrollmentDenied:
		return domain.ErrProxyEnrollmentDenied
	case domain.ProxyEnrollmentExpired:
		return domain.ErrProxyEnrollmentExpired
	case domain.ProxyEnrollmentConsumed:
		return domain.ErrProxyEnrollmentConsumed
	default:
		return domain.ErrProxyEnrollmentConflict
	}
}

func mapProxyEnrollmentWriteError(operation string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrProxyInstallationNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "proxy_installations_live_name_key" {
		return domain.ErrProxyInstallationNameConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}
