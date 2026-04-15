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
	"github.com/danielterry/dependency-firewall/migrations"
)

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

	policy := &domain.Policy{
		TenantID: tenant.ID,
		Name:     "block-critical",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   map[string]any{"threshold": 9.0},
		Priority: 10,
		Enabled:  true,
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
	assert.Equal(t, 10, got.Priority)
	assert.True(t, got.Enabled)
	assert.Equal(t, 9.0, got.Config["threshold"])
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
		Config:   map[string]any{},
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
			Config:   map[string]any{},
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
		Config:   map[string]any{"threshold": 7.0},
		Priority: 5,
		Enabled:  true,
	}
	require.NoError(t, repo.Create(ctx, policy))
	assert.Equal(t, 1, policy.Version)

	policy.Name = "updated"
	policy.Config = map[string]any{"threshold": 9.5}
	require.NoError(t, repo.Update(ctx, policy))
	assert.Equal(t, 2, policy.Version)

	got, err := repo.GetByID(ctx, tenant.ID, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated", got.Name)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, 9.5, got.Config["threshold"])
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
		Config:   map[string]any{},
		Priority: 1,
		Enabled:  true,
	}
	require.NoError(t, repo.Create(ctx, policy))
	require.NoError(t, repo.Delete(ctx, tenant.ID, policy.ID))

	_, err := repo.GetByID(ctx, tenant.ID, policy.ID)
	require.ErrorIs(t, err, domain.ErrPolicyNotFound)
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
		TenantID:  tenant.ID,
		Name:      "npm-registry",
		Ecosystem: domain.EcosystemNPM,
		BaseURL:   "https://registry.npmjs.org",
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
}

func TestUpstreamRepository_GetByEcosystem(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "eco-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	npm := &domain.Upstream{TenantID: tenant.ID, Name: "npm", Ecosystem: domain.EcosystemNPM, BaseURL: "https://registry.npmjs.org"}
	oci := &domain.Upstream{TenantID: tenant.ID, Name: "oci", Ecosystem: domain.EcosystemOCI, BaseURL: "https://ghcr.io"}
	require.NoError(t, repo.Create(ctx, npm))
	require.NoError(t, repo.Create(ctx, oci))

	gotNPM, err := repo.GetByEcosystem(ctx, tenant.ID, domain.EcosystemNPM)
	require.NoError(t, err)
	assert.Equal(t, npm.ID, gotNPM.ID)

	gotOCI, err := repo.GetByEcosystem(ctx, tenant.ID, domain.EcosystemOCI)
	require.NoError(t, err)
	assert.Equal(t, oci.ID, gotOCI.ID)
}

func TestUpstreamRepository_TenantIsolation(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenantA := createTestTenant(t, ctx, pool, "iso-a")
	tenantB := createTestTenant(t, ctx, pool, "iso-b")
	repo := postgres.NewUpstreamRepository(pool)

	upstream := &domain.Upstream{TenantID: tenantA.ID, Name: "npm", Ecosystem: domain.EcosystemNPM, BaseURL: "https://registry.npmjs.org"}
	require.NoError(t, repo.Create(ctx, upstream))

	_, err := repo.GetByID(ctx, tenantB.ID, upstream.ID)
	require.ErrorIs(t, err, domain.ErrUpstreamNotFound)

	list, err := repo.ListByTenant(ctx, tenantB.ID)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestUpstreamRepository_UniqueEcosystem(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "unique-eco-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	u1 := &domain.Upstream{TenantID: tenant.ID, Name: "npm-primary", Ecosystem: domain.EcosystemNPM, BaseURL: "https://registry.npmjs.org"}
	require.NoError(t, repo.Create(ctx, u1))

	u2 := &domain.Upstream{TenantID: tenant.ID, Name: "npm-secondary", Ecosystem: domain.EcosystemNPM, BaseURL: "https://other.npmjs.org"}
	err := repo.Create(ctx, u2)
	require.Error(t, err, "should fail due to unique tenant+ecosystem constraint")
}

func TestUpstreamRepository_ListByTenant(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, ctx, pool, "list-upstream-tenant")
	other := createTestTenant(t, ctx, pool, "other-upstream-tenant")
	repo := postgres.NewUpstreamRepository(pool)

	require.NoError(t, repo.Create(ctx, &domain.Upstream{TenantID: tenant.ID, Name: "npm", Ecosystem: domain.EcosystemNPM, BaseURL: "https://registry.npmjs.org"}))
	require.NoError(t, repo.Create(ctx, &domain.Upstream{TenantID: tenant.ID, Name: "oci", Ecosystem: domain.EcosystemOCI, BaseURL: "https://ghcr.io"}))
	require.NoError(t, repo.Create(ctx, &domain.Upstream{TenantID: other.ID, Name: "npm", Ecosystem: domain.EcosystemNPM, BaseURL: "https://registry.npmjs.org"}))

	list, err := repo.ListByTenant(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Len(t, list, 2)
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
		Config:   map[string]any{"threshold": 7.0},
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
		TenantID: tenant.ID,
		Artifact: artifact,
		Outcome:  domain.DecisionDeny,
		PolicyID: policy.ID,
		Reason:   "CVSS score 9.8 exceeds threshold 7.0",
		Reasons: []domain.EvaluationReason{
			{
				PolicyID:   policy.ID,
				PolicyName: "cvss-block",
				Category:   domain.ReasonPolicyMatch,
				Action:     domain.PolicyActionDeny,
				Message:    "CVSS 9.8 > 7.0",
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
	assert.Equal(t, artifact.Name, got.Artifact.Name)
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
			Outcome: domain.DecisionAllow,
			Reason:  "allowed",
		}
		require.NoError(t, repo.Record(ctx, d))
	}

	all, err := repo.ListByTenant(ctx, tenant.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, all, 3)

	page, err := repo.ListByTenant(ctx, tenant.ID, 2, 0)
	require.NoError(t, err)
	assert.Len(t, page, 2)

	page2, err := repo.ListByTenant(ctx, tenant.ID, 2, 2)
	require.NoError(t, err)
	assert.Len(t, page2, 1)
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

	list, err := repo.ListByTenant(ctx, tenantB.ID, 10, 0)
	require.NoError(t, err)
	assert.Empty(t, list)
}
