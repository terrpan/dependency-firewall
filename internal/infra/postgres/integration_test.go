//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	pgmodule "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/infra/postgres"
	"github.com/danielterry/dependency-firewall/internal/infra/secrets"
	"github.com/danielterry/dependency-firewall/migrations"
)

func ptrFloat64(v float64) *float64 { return &v }
func intPtr(v int) *int             { return &v }

// setupTestDB starts a PostgreSQL container, runs migrations, and returns a pool.
func setupTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := pgmodule.Run(ctx,
		"postgres:16-alpine",
		pgmodule.WithDatabase("testdb"),
		pgmodule.WithUsername("test"),
		pgmodule.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pgContainer.Terminate(ctx))
	})

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// Run migrations.
	srcDriver, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err)

	m, err := migrate.NewWithSourceInstance("iofs", srcDriver, fmt.Sprintf("pgx5://%s", connStr[len("postgres://"):]))
	require.NoError(t, err)
	require.NoError(t, m.Up())

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	return pool
}

// createTestTenant inserts a tenant and returns it with generated fields populated.
func createTestTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) *domain.Tenant {
	t.Helper()
	repo := postgres.NewTenantRepository(pool)
	tenant := &domain.Tenant{Name: name}
	require.NoError(t, repo.Create(ctx, tenant))
	require.NotEmpty(t, tenant.ID)
	return tenant
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

func TestMigrations_UpAndDown(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := pgmodule.Run(ctx,
		"postgres:16-alpine",
		pgmodule.WithDatabase("testdb"),
		pgmodule.WithUsername("test"),
		pgmodule.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pgContainer.Terminate(ctx)) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	dbURL := fmt.Sprintf("pgx5://%s", connStr[len("postgres://"):])

	srcDriver, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err)

	m, err := migrate.NewWithSourceInstance("iofs", srcDriver, dbURL)
	require.NoError(t, err)

	// Up
	require.NoError(t, m.Up())

	// Down to 0
	require.NoError(t, m.Down())

	// Re-create source driver (consumed after Down)
	srcDriver2, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err)
	m2, err := migrate.NewWithSourceInstance("iofs", srcDriver2, dbURL)
	require.NoError(t, err)

	// Up again
	require.NoError(t, m2.Up())
}

func TestMigrations_BackfillScorecardCapabilityForLegacyNPMUpstreams(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := pgmodule.Run(ctx,
		"postgres:16-alpine",
		pgmodule.WithDatabase("testdb"),
		pgmodule.WithUsername("test"),
		pgmodule.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pgContainer.Terminate(ctx)) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	dbURL := fmt.Sprintf("pgx5://%s", connStr[len("postgres://"):])

	srcDriver, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err)
	m, err := migrate.NewWithSourceInstance("iofs", srcDriver, dbURL)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(16))

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	var tenantID string
	err = pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('legacy-upstream-tenant') RETURNING id`,
	).Scan(&tenantID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO upstreams (tenant_id, name, ecosystem, base_url, capabilities)
		 VALUES ($1, $2, $3, $4, $5)`,
		tenantID,
		"npmjs-legacy",
		"npm",
		"https://registry.npmjs.org",
		[]string{"publish_time", "licenses", "vulnerability_lookup"},
	)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(17))

	var capabilities []string
	err = pool.QueryRow(ctx,
		`SELECT capabilities FROM upstreams WHERE tenant_id = $1`,
		tenantID,
	).Scan(&capabilities)
	require.NoError(t, err)
	assert.Equal(t, []string{"publish_time", "licenses", "vulnerability_lookup", "scorecard_lookup"}, capabilities)
}

// ---------------------------------------------------------------------------
// TenantRepository
// ---------------------------------------------------------------------------

func TestTenantRepository_CreateAndGet(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantRepository(pool)

	tenant := &domain.Tenant{Name: "acme-corp"}
	require.NoError(t, repo.Create(ctx, tenant))

	require.NotEmpty(t, tenant.ID)
	assert.False(t, tenant.CreatedAt.IsZero())
	assert.False(t, tenant.UpdatedAt.IsZero())

	got, err := repo.GetByID(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, got.ID)
	assert.Equal(t, "acme-corp", got.Name)
}

func TestTenantRepository_GetNotFound(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantRepository(pool)

	_, err := repo.GetByID(ctx, "00000000-0000-0000-0000-000000000000")
	require.ErrorIs(t, err, domain.ErrTenantNotFound)
}

func TestTenantRepository_List(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantRepository(pool)

	createTestTenant(t, ctx, pool, "zulu-org")
	createTestTenant(t, ctx, pool, "alpha-org")
	createTestTenant(t, ctx, pool, "mike-org")

	tenants, err := repo.List(ctx)
	require.NoError(t, err)
	require.Len(t, tenants, 3)
	assert.Equal(t, "alpha-org", tenants[0].Name)
	assert.Equal(t, "mike-org", tenants[1].Name)
	assert.Equal(t, "zulu-org", tenants[2].Name)
}

func TestTenantRepository_Update(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantRepository(pool)

	tenant := createTestTenant(t, ctx, pool, "old-name")

	tenant.Name = "new-name"
	require.NoError(t, repo.Update(ctx, tenant))

	got, err := repo.GetByID(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-name", got.Name)
}

func TestTenantRepository_UpdateNotFound(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantRepository(pool)

	err := repo.Update(ctx, &domain.Tenant{ID: "00000000-0000-0000-0000-000000000000", Name: "x"})
	require.ErrorIs(t, err, domain.ErrTenantNotFound)
}

func TestTenantRepository_Delete(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantRepository(pool)

	tenant := createTestTenant(t, ctx, pool, "to-delete")
	require.NoError(t, repo.Delete(ctx, tenant.ID))

	_, err := repo.GetByID(ctx, tenant.ID)
	require.ErrorIs(t, err, domain.ErrTenantNotFound)
}

func TestTenantRepository_DeleteNotFound(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantRepository(pool)

	err := repo.Delete(ctx, "00000000-0000-0000-0000-000000000000")
	require.ErrorIs(t, err, domain.ErrTenantNotFound)
}

// ---------------------------------------------------------------------------
// PolicyRepository
// ---------------------------------------------------------------------------

func TestPolicyRepository_CreateAndGet(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "policy-tenant")
	repo := postgres.NewPolicyRepository(pool)
	upstreamRepo := postgres.NewUpstreamRepository(pool)

	upstream := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "npmjs",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	require.NoError(t, upstreamRepo.Create(ctx, upstream))

	policy := &domain.Policy{
		TenantID:   tenant.ID,
		UpstreamID: upstream.ID,
		Name:       "block-critical",
		Type:       domain.PolicyTypeCVSSThreshold,
		Action:     domain.PolicyActionDeny,
		Config:     &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(9.0)},
		Priority:   10,
		Enabled:    true,
	}
	require.NoError(t, repo.Create(ctx, policy))
	require.NotEmpty(t, policy.ID)
	assert.Equal(t, 1, policy.Version)

	got, err := repo.GetByID(ctx, tenant.ID, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.ID, got.ID)
	assert.Equal(t, tenant.ID, got.TenantID)
	assert.Equal(t, "block-critical", got.Name)
	assert.Equal(t, domain.PolicyTypeCVSSThreshold, got.Type)
	assert.Equal(t, domain.PolicyActionDeny, got.Action)
	assert.Equal(t, 1, got.SchemaVersion)
	assert.Equal(t, 10, got.Priority)
	assert.True(t, got.Enabled)
	assert.Equal(t, upstream.ID, got.UpstreamID)
	cfg, ok := got.Config.(*domain.CVSSThresholdPolicyConfig)
	require.True(t, ok)
	require.NotNil(t, cfg.MaxCVSS)
	assert.Equal(t, 9.0, *cfg.MaxCVSS)
}

func TestPolicyRepository_GetByIDReturnsDeprecatedConfigError(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "legacy-policy-tenant")
	repo := postgres.NewPolicyRepository(pool)

	var policyID string
	err := pool.QueryRow(ctx, `
		INSERT INTO policies (tenant_id, name, type, action, schema_version, config, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
		RETURNING id`,
		tenant.ID, "legacy-policy", string(domain.PolicyTypeMaximumAge), string(domain.PolicyActionDeny),
		1, `{"max_age_days":730,"enforce":"warn"}`, 1, true,
	).Scan(&policyID)
	require.NoError(t, err)

	_, err = repo.GetByID(ctx, tenant.ID, policyID)
	require.ErrorIs(t, err, domain.ErrDeprecatedPolicyConfig)
}

func TestPolicyMigration_TranslateEnforceToDryRun(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "legacy-policy-migration-tenant")
	repo := postgres.NewPolicyRepository(pool)

	var policyID string
	err := pool.QueryRow(ctx, `
		INSERT INTO policies (tenant_id, name, type, action, schema_version, config, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
		RETURNING id`,
		tenant.ID, "legacy-policy", string(domain.PolicyTypeMaximumAge), string(domain.PolicyActionDeny),
		1, `{"max_age_days":730,"enforce":"warn"}`, 1, true,
	).Scan(&policyID)
	require.NoError(t, err)

	_, err = pool.Exec(
		ctx,
		`INSERT INTO policy_versions (policy_id, version, name, type, action, schema_version, config, priority, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
		policyID,
		1,
		"legacy-policy",
		string(domain.PolicyTypeMaximumAge),
		string(domain.PolicyActionDeny),
		1,
		`{"max_age_days":730,"enforce":"warn"}`,
		1,
		true,
	)
	require.NoError(t, err)

	migrationSQL, err := migrations.FS.ReadFile("000009_translate_enforce_to_dry_run.up.sql")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(migrationSQL))
	require.NoError(t, err)

	got, err := repo.GetByID(ctx, tenant.ID, policyID)
	require.NoError(t, err)
	cfg, ok := got.Config.(*domain.MaximumAgePolicyConfig)
	require.True(t, ok)
	require.NotNil(t, cfg.MaxAgeDays)
	assert.Equal(t, 730, *cfg.MaxAgeDays)
	assert.True(t, cfg.DryRun)
}

func TestPolicyRepository_ListVersionsRetainsLatestThree(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "policy-version-history-tenant")
	repo := postgres.NewPolicyRepository(pool)

	policy := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "block-critical",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority: 1,
		Enabled:  true,
	}
	require.NoError(t, repo.Create(ctx, policy))

	for _, score := range []float64{8.0, 9.0, 9.5} {
		policy.Config = &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(score)}
		require.NoError(t, repo.Update(ctx, policy))
	}

	versions, err := repo.ListVersions(ctx, tenant.ID, policy.ID, domain.MaxRetainedPolicyVersions)
	require.NoError(t, err)
	require.Len(t, versions, 3)
	assert.Equal(t, []int{4, 3, 2}, []int{versions[0].Version, versions[1].Version, versions[2].Version})

	firstCfg, ok := versions[0].Config.(*domain.CVSSThresholdPolicyConfig)
	require.True(t, ok)
	require.NotNil(t, firstCfg.MaxCVSS)
	assert.Equal(t, 9.5, *firstCfg.MaxCVSS)
}

func TestPolicyRepository_RollbackToVersion(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "policy-rollback-tenant")
	repo := postgres.NewPolicyRepository(pool)
	upstreamRepo := postgres.NewUpstreamRepository(pool)

	upstream := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "npmjs",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	require.NoError(t, upstreamRepo.Create(ctx, upstream))

	policy := &domain.Policy{
		TenantID:   tenant.ID,
		UpstreamID: upstream.ID,
		Name:       "block-critical",
		Type:       domain.PolicyTypeCVSSThreshold,
		Action:     domain.PolicyActionDeny,
		Config:     &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority:   1,
		Enabled:    true,
	}
	require.NoError(t, repo.Create(ctx, policy))

	policy.Name = "block-critical-stricter"
	policy.Config = &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(9.0)}
	policy.Priority = 5
	require.NoError(t, repo.Update(ctx, policy))

	rolledBack, err := repo.RollbackToVersion(ctx, tenant.ID, policy.ID, 1)
	require.NoError(t, err)
	assert.Equal(t, 3, rolledBack.Version)
	assert.Equal(t, "block-critical", rolledBack.Name)
	assert.Equal(t, 1, rolledBack.Priority)
	assert.Equal(t, upstream.ID, rolledBack.UpstreamID)
	cfg, ok := rolledBack.Config.(*domain.CVSSThresholdPolicyConfig)
	require.True(t, ok)
	require.NotNil(t, cfg.MaxCVSS)
	assert.Equal(t, 7.0, *cfg.MaxCVSS)

	got, err := repo.GetByID(ctx, tenant.ID, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, 3, got.Version)
	assert.Equal(t, "block-critical", got.Name)
	assert.Equal(t, 1, got.Priority)
}

func TestPolicyRepository_TenantIsolation(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenantA := createTestTenant(t, ctx, pool, "tenant-a")
	tenantB := createTestTenant(t, ctx, pool, "tenant-b")
	repo := postgres.NewPolicyRepository(pool)

	policy := &domain.Policy{
		TenantID: tenantA.ID,
		Name:     "private-policy",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority: 1,
		Enabled:  true,
	}
	require.NoError(t, repo.Create(ctx, policy))

	_, err := repo.GetByID(ctx, tenantB.ID, policy.ID)
	require.ErrorIs(t, err, domain.ErrPolicyNotFound)

	policies, err := repo.ListByTenant(ctx, tenantB.ID)
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestPolicyRepository_ListByTenant(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "list-tenant")
	repo := postgres.NewPolicyRepository(pool)

	for _, p := range []struct {
		name     string
		priority int
	}{
		{"low-priority", 30},
		{"high-priority", 1},
		{"mid-priority", 15},
	} {
		policy := &domain.Policy{
			TenantID: tenant.ID,
			Name:     p.name,
			Type:     domain.PolicyTypeCVSSThreshold,
			Action:   domain.PolicyActionDeny,
			Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
			Priority: p.priority,
			Enabled:  true,
		}
		require.NoError(t, repo.Create(ctx, policy))
	}

	policies, err := repo.ListByTenant(ctx, tenant.ID)
	require.NoError(t, err)
	require.Len(t, policies, 3)
	assert.Equal(t, "high-priority", policies[0].Name)
	assert.Equal(t, "mid-priority", policies[1].Name)
	assert.Equal(t, "low-priority", policies[2].Name)
}

func TestPolicyRepository_Update(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "update-tenant")
	repo := postgres.NewPolicyRepository(pool)

	policy := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "original",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority: 5,
		Enabled:  true,
	}
	require.NoError(t, repo.Create(ctx, policy))
	assert.Equal(t, 1, policy.Version)

	policy.Name = "updated"
	policy.Config = &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(9.5)}
	require.NoError(t, repo.Update(ctx, policy))
	assert.Equal(t, 2, policy.Version)

	got, err := repo.GetByID(ctx, tenant.ID, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated", got.Name)
	assert.Equal(t, 2, got.Version)
	cfg, ok := got.Config.(*domain.CVSSThresholdPolicyConfig)
	require.True(t, ok)
	require.NotNil(t, cfg.MaxCVSS)
	assert.Equal(t, 9.5, *cfg.MaxCVSS)
}

func TestPolicyRepository_CreateReturnsConflictForDuplicateName(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "duplicate-policy-tenant")
	repo := postgres.NewPolicyRepository(pool)

	first := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "block-critical",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority: 1,
		Enabled:  true,
	}
	second := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "block-critical",
		Type:     domain.PolicyTypeMinimumAge,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.MinimumAgePolicyConfig{MinAgeDays: intPtr(30)},
		Priority: 2,
		Enabled:  true,
	}

	require.NoError(t, repo.Create(ctx, first))
	err := repo.Create(ctx, second)
	require.ErrorIs(t, err, domain.ErrPolicyNameConflict)
}

func TestPolicyRepository_UpdateReturnsConflictForDuplicateName(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "policy-update-conflict-tenant")
	repo := postgres.NewPolicyRepository(pool)

	first := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "first-policy",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority: 1,
		Enabled:  true,
	}
	second := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "second-policy",
		Type:     domain.PolicyTypeMinimumAge,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.MinimumAgePolicyConfig{MinAgeDays: intPtr(30)},
		Priority: 2,
		Enabled:  true,
	}

	require.NoError(t, repo.Create(ctx, first))
	require.NoError(t, repo.Create(ctx, second))

	second.Name = "first-policy"
	err := repo.Update(ctx, second)
	require.ErrorIs(t, err, domain.ErrPolicyNameConflict)
}

func TestPolicyRepository_Delete(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "delete-policy-tenant")
	repo := postgres.NewPolicyRepository(pool)

	policy := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "to-delete",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority: 1,
		Enabled:  true,
	}
	require.NoError(t, repo.Create(ctx, policy))
	require.NoError(t, repo.Delete(ctx, tenant.ID, policy.ID, false))

	_, err := repo.GetByID(ctx, tenant.ID, policy.ID)
	require.ErrorIs(t, err, domain.ErrPolicyNotFound)
}

func TestPolicyRevisionRepository_Create(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "policy-revision-tenant")
	repo := postgres.NewPolicyRevisionRepository(pool)

	first := &domain.PolicySetRevision{
		TenantID:   tenant.ID,
		PolicyHash: "hash-1",
	}
	require.NoError(t, repo.Create(ctx, first))
	assert.Equal(t, int64(1), first.Generation)
	assert.NotEmpty(t, first.ID)

	second := &domain.PolicySetRevision{
		TenantID:   tenant.ID,
		PolicyHash: "hash-2",
	}
	require.NoError(t, repo.Create(ctx, second))
	assert.Equal(t, int64(2), second.Generation)
	assert.NotEmpty(t, second.ID)
}

// ---------------------------------------------------------------------------
// UpstreamRepository
// ---------------------------------------------------------------------------

func TestUpstreamRepository_CreateAndGet(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "upstream-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	upstream := &domain.Upstream{
		TenantID:     tenant.ID,
		Name:         "npm-registry",
		Ecosystem:    domain.EcosystemNPM,
		BaseURL:      "https://registry.npmjs.org",
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemNPM),
	}
	require.NoError(t, repo.Create(ctx, upstream))
	require.NotEmpty(t, upstream.ID)

	got, err := repo.GetByID(ctx, tenant.ID, upstream.ID)
	require.NoError(t, err)
	assert.Equal(t, upstream.ID, got.ID)
	assert.Equal(t, tenant.ID, got.TenantID)
	assert.Equal(t, "npm-registry", got.Name)
	assert.Equal(t, domain.EcosystemNPM, got.Ecosystem)
	assert.Equal(t, "https://registry.npmjs.org", got.BaseURL)
	assert.Equal(t, domain.DefaultUpstreamCapabilities(domain.EcosystemNPM), got.Capabilities)
}

func TestUpstreamRepository_StoresEncryptedAuth(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "upstream-auth-tenant")
	codec, err := secrets.NewAESGCMCodec([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	repo := postgres.NewUpstreamRepository(pool, codec)

	upstream := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "private-oci",
		Ecosystem: domain.EcosystemOCI,
		BaseURL:   "https://ghcr.io",
		Auth: &domain.UpstreamAuth{
			Type:     domain.UpstreamAuthBasic,
			Username: "robot",
			Secret:   "registry-pat",
		},
	}
	require.NoError(t, repo.Create(ctx, upstream))
	require.False(t, upstream.Auth.UpdatedAt.IsZero())

	var storedSecret string
	require.NoError(
		t,
		pool.QueryRow(ctx, `SELECT auth_secret::text FROM upstreams WHERE id = $1`, upstream.ID).Scan(&storedSecret),
	)
	assert.NotContains(t, storedSecret, "registry-pat")

	got, err := repo.GetByID(ctx, tenant.ID, upstream.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Auth)
	assert.Equal(t, domain.UpstreamAuthBasic, got.Auth.Type)
	assert.Equal(t, "robot", got.Auth.Username)
	assert.Equal(t, "registry-pat", got.Auth.Secret)

	got.Name = "private-oci-updated"
	got.Auth = nil
	require.NoError(t, repo.Update(ctx, got))
	preserved, err := repo.GetByID(ctx, tenant.ID, upstream.ID)
	require.NoError(t, err)
	require.NotNil(t, preserved.Auth)
	assert.Equal(t, "registry-pat", preserved.Auth.Secret)

	preserved.Auth = &domain.UpstreamAuth{Type: domain.UpstreamAuthNone}
	require.NoError(t, repo.Update(ctx, preserved))
	cleared, err := repo.GetByID(ctx, tenant.ID, upstream.ID)
	require.NoError(t, err)
	assert.Nil(t, cleared.Auth)
}

func TestUpstreamRepository_GetByEcosystem(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "eco-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	npm := &domain.Upstream{
		TenantID:     tenant.ID,
		Name:         "npm",
		Ecosystem:    domain.EcosystemNPM,
		BaseURL:      "https://registry.npmjs.org",
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemNPM),
	}
	npmSecondary := &domain.Upstream{
		TenantID:     tenant.ID,
		Name:         "npm-secondary",
		Ecosystem:    domain.EcosystemNPM,
		BaseURL:      "https://registry.company.example",
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemNPM),
	}
	oci := &domain.Upstream{
		TenantID:     tenant.ID,
		Name:         "oci",
		Ecosystem:    domain.EcosystemOCI,
		BaseURL:      "https://ghcr.io",
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemOCI),
	}
	require.NoError(t, repo.Create(ctx, npm))
	require.NoError(t, repo.Create(ctx, npmSecondary))
	require.NoError(t, repo.Create(ctx, oci))

	npm.Name = "npm-refreshed"
	require.NoError(t, repo.Update(ctx, npm))

	gotNPM, err := repo.GetByEcosystem(ctx, tenant.ID, domain.EcosystemNPM)
	require.NoError(t, err)
	assert.Equal(t, npm.ID, gotNPM.ID)
	assert.Equal(t, domain.DefaultUpstreamCapabilities(domain.EcosystemNPM), gotNPM.Capabilities)

	gotOCI, err := repo.GetByEcosystem(ctx, tenant.ID, domain.EcosystemOCI)
	require.NoError(t, err)
	assert.Equal(t, oci.ID, gotOCI.ID)
	assert.Equal(t, domain.DefaultUpstreamCapabilities(domain.EcosystemOCI), gotOCI.Capabilities)
}

func TestUpstreamRepository_TenantIsolation(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenantA := createTestTenant(t, ctx, pool, "iso-a")
	tenantB := createTestTenant(t, ctx, pool, "iso-b")
	repo := postgres.NewUpstreamRepository(pool)

	upstream := &domain.Upstream{
		TenantID:  tenantA.ID,
		Name:      "npm",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	require.NoError(t, repo.Create(ctx, upstream))

	_, err := repo.GetByID(ctx, tenantB.ID, upstream.ID)
	require.ErrorIs(t, err, domain.ErrUpstreamNotFound)

	list, err := repo.ListByTenant(ctx, tenantB.ID)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestUpstreamRepository_AllowsMultipleSameEcosystem(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "multi-eco-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	u1 := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "npm-primary",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	require.NoError(t, repo.Create(ctx, u1))

	u2 := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "npm-secondary",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://other.npmjs.org",
	}
	require.NoError(t, repo.Create(ctx, u2))

	list, err := repo.ListByTenant(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestUpstreamRepository_UniqueRegistry(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "unique-registry-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	u1 := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "npm-primary",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	require.NoError(t, repo.Create(ctx, u1))

	u2 := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "npm-mirror",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	err := repo.Create(ctx, u2)
	require.ErrorIs(t, err, domain.ErrUpstreamRegistryConflict)
}

func TestUpstreamRepository_ListByTenant(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "list-upstream-tenant")
	other := createTestTenant(t, ctx, pool, "other-upstream-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	require.NoError(
		t,
		repo.Create(
			ctx,
			&domain.Upstream{
				TenantID:  tenant.ID,
				Name:      "npm",
				Ecosystem: domain.EcosystemNPM,
				BaseURL:   "https://registry.npmjs.org",
			},
		),
	)
	require.NoError(
		t,
		repo.Create(
			ctx,
			&domain.Upstream{
				TenantID:  tenant.ID,
				Name:      "oci",
				Ecosystem: domain.EcosystemOCI,
				BaseURL:   "https://ghcr.io",
			},
		),
	)
	require.NoError(
		t,
		repo.Create(
			ctx,
			&domain.Upstream{
				TenantID:  other.ID,
				Name:      "npm",
				Ecosystem: domain.EcosystemNPM,
				BaseURL:   "https://registry.npmjs.org",
			},
		),
	)

	list, err := repo.ListByTenant(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestUpstreamRepository_DeleteRejectsReferencedPolicy(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "upstream-policy-ref-tenant")
	upstreamRepo := postgres.NewUpstreamRepository(pool)
	policyRepo := postgres.NewPolicyRepository(pool)

	upstream := &domain.Upstream{
		TenantID:  tenant.ID,
		Name:      "npmjs",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
	}
	require.NoError(t, upstreamRepo.Create(ctx, upstream))

	policy := &domain.Policy{
		TenantID:      tenant.ID,
		UpstreamID:    upstream.ID,
		Name:          "block-critical",
		Type:          domain.PolicyTypeCVSSThreshold,
		Action:        domain.PolicyActionDeny,
		SchemaVersion: 1,
		Config:        &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(9.0)},
		Priority:      10,
		Enabled:       true,
	}
	require.NoError(t, policyRepo.Create(ctx, policy))

	err := upstreamRepo.Delete(ctx, tenant.ID, upstream.ID)
	require.ErrorIs(t, err, domain.ErrUpstreamInUse)
}

func TestPolicyRepository_DeleteRejectsReferencedEvaluation(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "policy-evaluation-ref-tenant")
	policyRepo := postgres.NewPolicyRepository(pool)

	policy := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "block-critical",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(9.0)},
		Priority: 10,
		Enabled:  false,
	}
	require.NoError(t, policyRepo.Create(ctx, policy))

	_, err := pool.Exec(ctx,
		`INSERT INTO evaluations (tenant_id, outcome, policy_id, reason) VALUES ($1, $2, $3, $4)`,
		tenant.ID, "deny", policy.ID, "policy matched",
	)
	require.NoError(t, err)

	err = policyRepo.Delete(ctx, tenant.ID, policy.ID, false)
	require.ErrorIs(t, err, domain.ErrPolicyInUse)
}

func TestPolicyRepository_ForceDeleteClearsHistoricalReferences(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "policy-force-delete-tenant")
	policyRepo := postgres.NewPolicyRepository(pool)

	policy := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "block-critical",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(9.0)},
		Priority: 10,
		Enabled:  false,
	}
	require.NoError(t, policyRepo.Create(ctx, policy))

	var evaluationID string
	err := pool.QueryRow(ctx,
		`INSERT INTO evaluations (tenant_id, outcome, policy_id, reason) VALUES ($1, $2, $3, $4) RETURNING id`,
		tenant.ID, "deny", policy.ID, "policy matched",
	).Scan(&evaluationID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO evaluation_reasons (evaluation_id, policy_id, policy_name, category, action, message)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		evaluationID, policy.ID, policy.Name, "policy", "deny", "blocked by policy",
	)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO decisions (tenant_id, outcome, policy_id, reason) VALUES ($1, $2, $3, $4)`,
		tenant.ID, "deny", policy.ID, "policy matched",
	)
	require.NoError(t, err)

	err = policyRepo.Delete(ctx, tenant.ID, policy.ID, true)
	require.NoError(t, err)

	_, err = policyRepo.GetByID(ctx, tenant.ID, policy.ID)
	require.ErrorIs(t, err, domain.ErrPolicyNotFound)

	var evaluationPolicyID *string
	err = pool.QueryRow(ctx, `SELECT policy_id FROM evaluations WHERE id = $1`, evaluationID).Scan(&evaluationPolicyID)
	require.NoError(t, err)
	assert.Nil(t, evaluationPolicyID)

	var decisionPolicyID *string
	err = pool.QueryRow(ctx, `SELECT policy_id FROM decisions WHERE tenant_id = $1 LIMIT 1`, tenant.ID).
		Scan(&decisionPolicyID)
	require.NoError(t, err)
	assert.Nil(t, decisionPolicyID)

	var reasonPolicyID *string
	err = pool.QueryRow(ctx, `SELECT policy_id FROM evaluation_reasons WHERE evaluation_id = $1`, evaluationID).
		Scan(&reasonPolicyID)
	require.NoError(t, err)
	assert.Nil(t, reasonPolicyID)
}

// ---------------------------------------------------------------------------
// DecisionRepository
// ---------------------------------------------------------------------------

func TestDecisionRepository_RecordAndGet(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "decision-tenant")

	// Create a policy to reference in reasons.
	policyRepo := postgres.NewPolicyRepository(pool)
	policy := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "cvss-block",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)},
		Priority: 1,
		Enabled:  true,
	}
	require.NoError(t, policyRepo.Create(ctx, policy))

	repo := postgres.NewDecisionRepository(pool)

	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Namespace: "@acme",
		Name:      "widget",
		Version:   "1.2.3",
		Digest:    "sha256:abc123",
	}
	decision := &domain.Decision{
		TenantID:   tenant.ID,
		Artifact:   artifact,
		Outcome:    domain.DecisionDeny,
		PolicyID:   policy.ID,
		PolicyHash: "policy-hash-1",
		Reason:     "CVSS score 9.8 at or above threshold 7.0",
		Warnings:   []string{"[cvss-block] would block in dry run"},
		Reasons: []domain.EvaluationReason{
			{
				PolicyID:   policy.ID,
				PolicyName: "cvss-block",
				Category:   domain.ReasonPolicyMatch,
				Action:     domain.PolicyActionDeny,
				Message:    "CVSS 9.8 >= 7.0",
			},
		},
	}
	require.NoError(t, repo.Record(ctx, decision))
	require.NotEmpty(t, decision.ID)
	assert.False(t, decision.EvaluatedAt.IsZero())

	got, err := repo.GetByArtifact(ctx, tenant.ID, artifact)
	require.NoError(t, err)
	assert.Equal(t, decision.ID, got.ID)
	assert.Equal(t, domain.DecisionDeny, got.Outcome)
	assert.Equal(t, policy.ID, got.PolicyID)
	assert.Equal(t, "policy-hash-1", got.PolicyHash)
	assert.Equal(t, artifact.Name, got.Artifact.Name)
	assert.Equal(t, []string{"[cvss-block] would block in dry run"}, got.Warnings)
}

func TestDecisionRepository_ListByTenant(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "list-decision-tenant")
	repo := postgres.NewDecisionRepository(pool)

	for i := range 3 {
		d := &domain.Decision{
			TenantID: tenant.ID,
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      fmt.Sprintf("pkg-%d", i),
				Version:   "1.0.0",
			},
			Outcome:    domain.DecisionAllow,
			PolicyHash: fmt.Sprintf("policy-hash-%d", i),
			Reason:     "allowed",
		}
		require.NoError(t, repo.Record(ctx, d))
	}

	all, err := repo.ListByTenant(ctx, tenant.ID, 10, 0, "")
	require.NoError(t, err)
	assert.Len(t, all, 3)
	assert.NotEmpty(t, all[0].PolicyHash)

	page, err := repo.ListByTenant(ctx, tenant.ID, 2, 0, "")
	require.NoError(t, err)
	assert.Len(t, page, 2)

	page2, err := repo.ListByTenant(ctx, tenant.ID, 2, 2, "")
	require.NoError(t, err)
	assert.Len(t, page2, 1)
}

func TestDecisionRepository_ListByTenant_WithSearch(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "search-decision-tenant")
	repo := postgres.NewDecisionRepository(pool)

	require.NoError(t, repo.Record(ctx, &domain.Decision{
		TenantID: tenant.ID,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "lodash",
			Version:   "4.17.20",
		},
		Outcome:  domain.DecisionAllow,
		Reason:   "allowed",
		Warnings: []string{"[block-cvss] artifact would be denied in dry run"},
	}))
	require.NoError(t, repo.Record(ctx, &domain.Decision{
		TenantID: tenant.ID,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "@acme",
			Name:      "widget",
			Version:   "1.2.3",
		},
		Outcome: domain.DecisionAllow,
		Reason:  "allowed",
	}))

	byName, err := repo.ListByTenant(ctx, tenant.ID, 10, 0, "lodash")
	require.NoError(t, err)
	require.Len(t, byName, 1)
	assert.Equal(t, "lodash", byName[0].Artifact.Name)
	assert.Equal(t, []string{"[block-cvss] artifact would be denied in dry run"}, byName[0].Warnings)

	byQualifiedName, err := repo.ListByTenant(ctx, tenant.ID, 10, 0, "@acme/widget")
	require.NoError(t, err)
	require.Len(t, byQualifiedName, 1)
	assert.Equal(t, "@acme", byQualifiedName[0].Artifact.Namespace)
	assert.Equal(t, "widget", byQualifiedName[0].Artifact.Name)

	byVersion, err := repo.ListByTenant(ctx, tenant.ID, 10, 0, "4.17.20")
	require.NoError(t, err)
	require.Len(t, byVersion, 1)
	assert.Equal(t, "lodash", byVersion[0].Artifact.Name)
}

func TestDecisionRepository_HasRecentAllow(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "recent-allow-tenant")
	repo := postgres.NewDecisionRepository(pool)

	// Record an allow decision.
	allow := &domain.Decision{
		TenantID: tenant.ID,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "@acme",
			Name:      "allowed-pkg",
			Version:   "1.0.0",
		},
		Outcome: domain.DecisionAllow,
		Reason:  "ok",
	}
	require.NoError(t, repo.Record(ctx, allow))

	hasAllow, err := repo.HasRecentAllow(ctx, tenant.ID, domain.EcosystemNPM, "@acme", "allowed-pkg")
	require.NoError(t, err)
	assert.True(t, hasAllow)

	// Record a deny for a different artifact.
	deny := &domain.Decision{
		TenantID: tenant.ID,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "@acme",
			Name:      "denied-pkg",
			Version:   "2.0.0",
		},
		Outcome: domain.DecisionDeny,
		Reason:  "blocked",
	}
	require.NoError(t, repo.Record(ctx, deny))

	hasDeny, err := repo.HasRecentAllow(ctx, tenant.ID, domain.EcosystemNPM, "@acme", "denied-pkg")
	require.NoError(t, err)
	assert.False(t, hasDeny)
}

func TestDecisionRepository_TenantIsolation(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenantA := createTestTenant(t, ctx, pool, "dec-iso-a")
	tenantB := createTestTenant(t, ctx, pool, "dec-iso-b")
	repo := postgres.NewDecisionRepository(pool)

	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "shared-name",
		Version:   "1.0.0",
	}
	require.NoError(t, repo.Record(ctx, &domain.Decision{
		TenantID: tenantA.ID,
		Artifact: artifact,
		Outcome:  domain.DecisionAllow,
		Reason:   "ok",
	}))

	_, err := repo.GetByArtifact(ctx, tenantB.ID, artifact)
	require.ErrorIs(t, err, domain.ErrArtifactNotFound)

	list, err := repo.ListByTenant(ctx, tenantB.ID, 10, 0, "")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestAuditEventRepository_RecordAndListByTenant(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenantA := createTestTenant(t, ctx, pool, "audit-tenant-a")
	tenantB := createTestTenant(t, ctx, pool, "audit-tenant-b")
	repo := postgres.NewAuditEventRepository(pool)
	now := time.Now().UTC()

	require.NoError(t, repo.Record(ctx, &domain.AuditEvent{
		TenantID:      tenantA.ID,
		CorrelationID: "req-20260503-101500-abcd12",
		EventType:     domain.AuditEventDecisionComputed,
		Source:        "core/access",
		EntityType:    "decision",
		UpstreamID:    "upstream-a",
		PolicyID:      "policy-a",
		Outcome:       domain.DecisionDeny,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "@acme",
			Name:      "lodash",
			Version:   "4.17.20",
		},
		Message: "decision computed",
		Payload: map[string]any{
			"reason": "blocked",
		},
		CreatedAt: now,
	}))
	require.NoError(t, repo.Record(ctx, &domain.AuditEvent{
		TenantID:      tenantA.ID,
		CorrelationID: "req-20260503-101600-ffff00",
		EventType:     domain.AuditEventRequestAllowed,
		Source:        "delivery/npm",
		Outcome:       domain.DecisionAllow,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "widget",
			Version:   "1.2.3",
		},
		Message:   "request allowed",
		CreatedAt: now.Add(1 * time.Minute),
	}))
	require.NoError(t, repo.Record(ctx, &domain.AuditEvent{
		TenantID:      tenantB.ID,
		CorrelationID: "req-other",
		EventType:     domain.AuditEventRequestDenied,
		Source:        "delivery/oci",
		Outcome:       domain.DecisionDeny,
		Message:       "other tenant event",
		CreatedAt:     now,
	}))

	events, err := repo.ListByTenant(ctx, domain.AuditEventFilter{
		TenantID:  tenantA.ID,
		Limit:     10,
		EventType: domain.AuditEventDecisionComputed,
		Outcome:   domain.DecisionDeny,
		Search:    "lodash",
	})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "req-20260503-101500-abcd12", events[0].CorrelationID)
	assert.Equal(t, "policy-a", events[0].PolicyID)
	assert.Equal(t, "blocked", events[0].Payload["reason"])

	events, err = repo.ListByTenant(ctx, domain.AuditEventFilter{
		TenantID:      tenantA.ID,
		Limit:         10,
		CorrelationID: "req-20260503-101600-ffff00",
		Source:        "delivery/npm",
	})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, domain.AuditEventRequestAllowed, events[0].EventType)
	assert.Equal(t, "widget", events[0].Artifact.Name)
}
