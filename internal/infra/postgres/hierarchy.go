package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type TenantIdentityLinkRepository struct{ pool *pgxpool.Pool }

func NewTenantIdentityLinkRepository(pool *pgxpool.Pool) *TenantIdentityLinkRepository {
	return &TenantIdentityLinkRepository{pool: pool}
}

func (r *TenantIdentityLinkRepository) GetByExternalID(ctx context.Context, provider, externalID string) (*domain.TenantIdentityLink, error) {
	var link domain.TenantIdentityLink
	err := r.pool.QueryRow(ctx,
		`SELECT tenant_id, provider, external_id, created_at, updated_at
		 FROM tenant_identity_links
		 WHERE provider = $1 AND external_id = $2`, provider, externalID,
	).Scan(&link.TenantID, &link.Provider, &link.ExternalID, &link.CreatedAt, &link.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrTenantIdentityLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying tenant identity link: %w", err)
	}
	return &link, nil
}

func (r *TenantIdentityLinkRepository) Create(ctx context.Context, link *domain.TenantIdentityLink) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO tenant_identity_links (tenant_id, provider, external_id)
		 VALUES ($1, $2, $3)
		 RETURNING created_at, updated_at`,
		link.TenantID, link.Provider, link.ExternalID,
	).Scan(&link.CreatedAt, &link.UpdatedAt)
	if err != nil {
		if isConstraint(err, "tenant_identity_links_pkey") || isConstraint(err, "tenant_identity_links_provider_external_key") {
			return domain.ErrTenantIdentityLinkConflict
		}
		return fmt.Errorf("creating tenant identity link: %w", err)
	}
	return nil
}

type PrincipalRepository struct{ pool *pgxpool.Pool }

func NewPrincipalRepository(pool *pgxpool.Pool) *PrincipalRepository {
	return &PrincipalRepository{pool: pool}
}

func (r *PrincipalRepository) GetByID(ctx context.Context, id string) (*domain.Principal, error) {
	return scanPrincipal(r.pool.QueryRow(ctx,
		`SELECT id, display_name, email, status, created_at, updated_at
		 FROM principals WHERE id = $1`, id,
	))
}

func (r *PrincipalRepository) GetByIdentity(ctx context.Context, provider, externalSubject string) (*domain.Principal, error) {
	return scanPrincipal(r.pool.QueryRow(ctx,
		`SELECT p.id, p.display_name, p.email, p.status, p.created_at, p.updated_at
		 FROM principals p
		 JOIN principal_identities i ON i.principal_id = p.id
		 WHERE i.provider = $1 AND i.external_subject = $2`, provider, externalSubject,
	))
}

func (r *PrincipalRepository) GetIdentity(ctx context.Context, principalID, provider string) (*domain.PrincipalIdentity, error) {
	var identity domain.PrincipalIdentity
	err := r.pool.QueryRow(ctx,
		`SELECT principal_id, provider, external_subject, created_at
		 FROM principal_identities WHERE principal_id = $1 AND provider = $2`, principalID, provider,
	).Scan(&identity.PrincipalID, &identity.Provider, &identity.ExternalSubject, &identity.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPrincipalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying principal identity: %w", err)
	}
	return &identity, nil
}

func scanPrincipal(row pgx.Row) (*domain.Principal, error) {
	var principal domain.Principal
	err := row.Scan(
		&principal.ID,
		&principal.DisplayName,
		&principal.Email,
		&principal.Status,
		&principal.CreatedAt,
		&principal.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPrincipalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying principal: %w", err)
	}
	return &principal, nil
}

func (r *PrincipalRepository) Create(ctx context.Context, principal *domain.Principal) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO principals (display_name, email, status)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at, updated_at`,
		principal.DisplayName, principal.Email, principal.Status,
	).Scan(&principal.ID, &principal.CreatedAt, &principal.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating principal: %w", err)
	}
	return nil
}

func (r *PrincipalRepository) Update(ctx context.Context, principal *domain.Principal) error {
	err := r.pool.QueryRow(ctx,
		`UPDATE principals
		 SET display_name = $1, email = $2, status = $3, updated_at = now()
		 WHERE id = $4
		 RETURNING updated_at`,
		principal.DisplayName, principal.Email, principal.Status, principal.ID,
	).Scan(&principal.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrPrincipalNotFound
	}
	if err != nil {
		return fmt.Errorf("updating principal: %w", err)
	}
	return nil
}

func (r *PrincipalRepository) LinkIdentity(ctx context.Context, identity *domain.PrincipalIdentity) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO principal_identities (principal_id, provider, external_subject)
		 VALUES ($1, $2, $3)
		 RETURNING created_at`,
		identity.PrincipalID, identity.Provider, identity.ExternalSubject,
	).Scan(&identity.CreatedAt)
	if err != nil {
		if isConstraint(err, "principal_identities_pkey") || isConstraint(err, "principal_identities_principal_provider_key") {
			return domain.ErrPrincipalIdentityConflict
		}
		return fmt.Errorf("linking principal identity: %w", err)
	}
	return nil
}

type OrganizationRepository struct{ pool *pgxpool.Pool }

func NewOrganizationRepository(pool *pgxpool.Pool) *OrganizationRepository {
	return &OrganizationRepository{pool: pool}
}

func (r *OrganizationRepository) GetByID(ctx context.Context, tenantID, id string) (*domain.Organization, error) {
	return scanOrganization(r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, status, is_default, created_at, updated_at
		 FROM organizations WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	))
}

func (r *OrganizationRepository) GetDefault(ctx context.Context, tenantID string) (*domain.Organization, error) {
	return scanOrganization(r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, status, is_default, created_at, updated_at
		 FROM organizations WHERE tenant_id = $1 AND is_default`, tenantID,
	))
}

func scanOrganization(row pgx.Row) (*domain.Organization, error) {
	var organization domain.Organization
	err := row.Scan(
		&organization.ID,
		&organization.TenantID,
		&organization.Name,
		&organization.Status,
		&organization.IsDefault,
		&organization.CreatedAt,
		&organization.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrOrganizationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying organization: %w", err)
	}
	return &organization, nil
}

func (r *OrganizationRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.Organization, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, name, status, is_default, created_at, updated_at
		 FROM organizations WHERE tenant_id = $1 ORDER BY is_default DESC, name, id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing organizations: %w", err)
	}
	defer rows.Close()

	var organizations []domain.Organization
	for rows.Next() {
		var organization domain.Organization
		if err := rows.Scan(
			&organization.ID,
			&organization.TenantID,
			&organization.Name,
			&organization.Status,
			&organization.IsDefault,
			&organization.CreatedAt,
			&organization.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning organization: %w", err)
		}
		organizations = append(organizations, organization)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating organizations: %w", err)
	}
	return organizations, nil
}

func (r *OrganizationRepository) Create(ctx context.Context, organization *domain.Organization) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO organizations (tenant_id, name, status, is_default)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at, updated_at`,
		organization.TenantID, organization.Name, organization.Status, organization.IsDefault,
	).Scan(&organization.ID, &organization.CreatedAt, &organization.UpdatedAt)
	if err != nil {
		if isConstraint(err, "organizations_tenant_name_key") || isConstraint(err, "organizations_one_default_per_tenant") {
			return domain.ErrOrganizationNameConflict
		}
		return fmt.Errorf("creating organization: %w", err)
	}
	return nil
}

func (r *OrganizationRepository) Update(ctx context.Context, organization *domain.Organization) error {
	err := r.pool.QueryRow(ctx,
		`UPDATE organizations
		 SET name = $1, status = $2, updated_at = now()
		 WHERE tenant_id = $3 AND id = $4
		 RETURNING updated_at`,
		organization.Name, organization.Status, organization.TenantID, organization.ID,
	).Scan(&organization.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrOrganizationNotFound
	}
	if err != nil {
		if isConstraint(err, "organizations_tenant_name_key") {
			return domain.ErrOrganizationNameConflict
		}
		return fmt.Errorf("updating organization: %w", err)
	}
	return nil
}

type OrganizationMembershipRepository struct{ pool *pgxpool.Pool }

func NewOrganizationMembershipRepository(pool *pgxpool.Pool) *OrganizationMembershipRepository {
	return &OrganizationMembershipRepository{pool: pool}
}

func (r *OrganizationMembershipRepository) Get(ctx context.Context, tenantID, organizationID, principalID string) (*domain.OrganizationMembership, error) {
	var membership domain.OrganizationMembership
	err := r.pool.QueryRow(ctx,
		`SELECT tenant_id, organization_id, principal_id, role, created_at, updated_at
		 FROM organization_memberships
		 WHERE tenant_id = $1 AND organization_id = $2 AND principal_id = $3`,
		tenantID, organizationID, principalID,
	).Scan(
		&membership.TenantID,
		&membership.OrganizationID,
		&membership.PrincipalID,
		&membership.Role,
		&membership.CreatedAt,
		&membership.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrOrganizationMembershipNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying organization membership: %w", err)
	}
	return &membership, nil
}

func (r *OrganizationMembershipRepository) ListByPrincipal(ctx context.Context, tenantID, principalID string) ([]domain.OrganizationMembership, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT tenant_id, organization_id, principal_id, role, created_at, updated_at
		 FROM organization_memberships
		 WHERE tenant_id = $1 AND principal_id = $2
		 ORDER BY organization_id`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("listing organization memberships: %w", err)
	}
	defer rows.Close()

	var memberships []domain.OrganizationMembership
	for rows.Next() {
		var membership domain.OrganizationMembership
		if err := rows.Scan(
			&membership.TenantID,
			&membership.OrganizationID,
			&membership.PrincipalID,
			&membership.Role,
			&membership.CreatedAt,
			&membership.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning organization membership: %w", err)
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating organization memberships: %w", err)
	}
	return memberships, nil
}

func (r *OrganizationMembershipRepository) Upsert(ctx context.Context, membership *domain.OrganizationMembership) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO organization_memberships (tenant_id, organization_id, principal_id, role)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (organization_id, principal_id)
		 DO UPDATE SET role = EXCLUDED.role, updated_at = now()
		 RETURNING created_at, updated_at`,
		membership.TenantID, membership.OrganizationID, membership.PrincipalID, membership.Role,
	).Scan(&membership.CreatedAt, &membership.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upserting organization membership: %w", err)
	}
	return nil
}

func (r *OrganizationMembershipRepository) Delete(ctx context.Context, tenantID, organizationID, principalID string) error {
	result, err := r.pool.Exec(ctx,
		`DELETE FROM organization_memberships
		 WHERE tenant_id = $1 AND organization_id = $2 AND principal_id = $3`,
		tenantID, organizationID, principalID,
	)
	if err != nil {
		return fmt.Errorf("deleting organization membership: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrOrganizationMembershipNotFound
	}
	return nil
}

type TeamRepository struct{ pool *pgxpool.Pool }

func NewTeamRepository(pool *pgxpool.Pool) *TeamRepository {
	return &TeamRepository{pool: pool}
}

func (r *TeamRepository) GetByID(ctx context.Context, tenantID, organizationID, id string) (*domain.Team, error) {
	return scanTeam(r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, organization_id, name, archived_at, created_at, updated_at
		 FROM teams WHERE tenant_id = $1 AND organization_id = $2 AND id = $3`,
		tenantID, organizationID, id,
	))
}

func scanTeam(row pgx.Row) (*domain.Team, error) {
	var team domain.Team
	err := row.Scan(
		&team.ID,
		&team.TenantID,
		&team.OrganizationID,
		&team.Name,
		&team.ArchivedAt,
		&team.CreatedAt,
		&team.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrTeamNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying team: %w", err)
	}
	return &team, nil
}

func (r *TeamRepository) ListByOrganization(ctx context.Context, tenantID, organizationID string) ([]domain.Team, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, organization_id, name, archived_at, created_at, updated_at
		 FROM teams
		 WHERE tenant_id = $1 AND organization_id = $2
		 ORDER BY archived_at NULLS FIRST, name, id`, tenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("listing teams: %w", err)
	}
	defer rows.Close()

	var teams []domain.Team
	for rows.Next() {
		var team domain.Team
		if err := rows.Scan(
			&team.ID,
			&team.TenantID,
			&team.OrganizationID,
			&team.Name,
			&team.ArchivedAt,
			&team.CreatedAt,
			&team.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning team: %w", err)
		}
		teams = append(teams, team)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating teams: %w", err)
	}
	return teams, nil
}

func (r *TeamRepository) Create(ctx context.Context, team *domain.Team) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO teams (tenant_id, organization_id, name, archived_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at, updated_at`,
		team.TenantID, team.OrganizationID, team.Name, team.ArchivedAt,
	).Scan(&team.ID, &team.CreatedAt, &team.UpdatedAt)
	if err != nil {
		if isConstraint(err, "teams_organization_name_key") {
			return domain.ErrTeamNameConflict
		}
		return fmt.Errorf("creating team: %w", err)
	}
	return nil
}

func (r *TeamRepository) Update(ctx context.Context, team *domain.Team) error {
	err := r.pool.QueryRow(ctx,
		`UPDATE teams
		 SET name = $1, archived_at = $2, updated_at = now()
		 WHERE tenant_id = $3 AND organization_id = $4 AND id = $5
		 RETURNING updated_at`,
		team.Name, team.ArchivedAt, team.TenantID, team.OrganizationID, team.ID,
	).Scan(&team.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrTeamNotFound
	}
	if err != nil {
		if isConstraint(err, "teams_organization_name_key") {
			return domain.ErrTeamNameConflict
		}
		return fmt.Errorf("updating team: %w", err)
	}
	return nil
}

type TeamMembershipRepository struct{ pool *pgxpool.Pool }

func NewTeamMembershipRepository(pool *pgxpool.Pool) *TeamMembershipRepository {
	return &TeamMembershipRepository{pool: pool}
}

func (r *TeamMembershipRepository) IsMember(ctx context.Context, tenantID, organizationID, teamID, principalID string) (bool, error) {
	var member bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM team_memberships
			WHERE tenant_id = $1 AND organization_id = $2 AND team_id = $3 AND principal_id = $4
		)`, tenantID, organizationID, teamID, principalID,
	).Scan(&member)
	if err != nil {
		return false, fmt.Errorf("querying team membership: %w", err)
	}
	return member, nil
}

func (r *TeamMembershipRepository) ListByPrincipal(ctx context.Context, tenantID, organizationID, principalID string) ([]domain.TeamMembership, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT tenant_id, organization_id, team_id, principal_id, created_at
		 FROM team_memberships
		 WHERE tenant_id = $1 AND organization_id = $2 AND principal_id = $3
		 ORDER BY team_id`, tenantID, organizationID, principalID)
	if err != nil {
		return nil, fmt.Errorf("listing team memberships: %w", err)
	}
	defer rows.Close()

	var memberships []domain.TeamMembership
	for rows.Next() {
		var membership domain.TeamMembership
		if err := rows.Scan(
			&membership.TenantID,
			&membership.OrganizationID,
			&membership.TeamID,
			&membership.PrincipalID,
			&membership.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning team membership: %w", err)
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating team memberships: %w", err)
	}
	return memberships, nil
}

func (r *TeamMembershipRepository) Upsert(ctx context.Context, membership *domain.TeamMembership) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO team_memberships (tenant_id, organization_id, team_id, principal_id)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (team_id, principal_id) DO NOTHING
		 RETURNING created_at`,
		membership.TenantID, membership.OrganizationID, membership.TeamID, membership.PrincipalID,
	).Scan(&membership.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r.pool.QueryRow(ctx,
			`SELECT created_at FROM team_memberships
			 WHERE tenant_id = $1 AND organization_id = $2 AND team_id = $3 AND principal_id = $4`,
			membership.TenantID, membership.OrganizationID, membership.TeamID, membership.PrincipalID,
		).Scan(&membership.CreatedAt)
	}
	if err != nil {
		return fmt.Errorf("upserting team membership: %w", err)
	}
	return nil
}

func (r *TeamMembershipRepository) Delete(ctx context.Context, tenantID, organizationID, teamID, principalID string) error {
	result, err := r.pool.Exec(ctx,
		`DELETE FROM team_memberships
		 WHERE tenant_id = $1 AND organization_id = $2 AND team_id = $3 AND principal_id = $4`,
		tenantID, organizationID, teamID, principalID,
	)
	if err != nil {
		return fmt.Errorf("deleting team membership: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrTeamMembershipNotFound
	}
	return nil
}
