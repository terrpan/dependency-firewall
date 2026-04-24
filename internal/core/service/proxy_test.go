package service

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type spyPolicyRepository struct {
	policies          []domain.Policy
	listByTenantCalls int
	lastTenantID      string
	listErr           error
}

func proxyIntPtr(v int) *int { return &v }

func (s *spyPolicyRepository) GetByID(context.Context, string, string) (*domain.Policy, error) {
	return nil, domain.ErrPolicyNotFound
}

func (s *spyPolicyRepository) ListByTenant(_ context.Context, tenantID string) ([]domain.Policy, error) {
	s.listByTenantCalls++
	s.lastTenantID = tenantID
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.policies, nil
}

func (s *spyPolicyRepository) ListVersions(context.Context, string, string, int) ([]domain.PolicyVersion, error) {
	return nil, domain.ErrPolicyNotFound
}

func (s *spyPolicyRepository) RollbackToVersion(context.Context, string, string, int) (*domain.Policy, error) {
	return nil, domain.ErrPolicyNotFound
}

func (s *spyPolicyRepository) Create(context.Context, *domain.Policy) error {
	return nil
}

func (s *spyPolicyRepository) Update(context.Context, *domain.Policy) error {
	return nil
}

func (s *spyPolicyRepository) Delete(context.Context, string, string) error {
	return nil
}

type spyDecisionRepository struct {
	recordCalls int
	recorded    []domain.Decision
}

func (s *spyDecisionRepository) Record(_ context.Context, decision *domain.Decision) error {
	s.recordCalls++
	s.recorded = append(s.recorded, *decision)
	return nil
}

func (s *spyDecisionRepository) GetByArtifact(context.Context, string, domain.ArtifactIdentity) (*domain.Decision, error) {
	return nil, domain.ErrArtifactNotFound
}

func (s *spyDecisionRepository) ListByTenant(context.Context, string, int, int) ([]domain.Decision, error) {
	return nil, nil
}

func (s *spyDecisionRepository) HasRecentAllow(context.Context, string, domain.EcosystemType, string, string) (bool, error) {
	return false, nil
}

type spyDecisionCache struct {
	getErr          error
	lastGetTenantID string
	lastGetArtifact domain.ArtifactIdentity
	setCalls        int
	lastDecision    *domain.Decision
	lastTTL         time.Duration
}

func newSpyDecisionCache() *spyDecisionCache {
	return &spyDecisionCache{getErr: domain.ErrCacheMiss}
}

func (s *spyDecisionCache) Get(_ context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	s.lastGetTenantID = tenantID
	s.lastGetArtifact = artifact
	return nil, s.getErr
}

func (s *spyDecisionCache) Set(_ context.Context, decision *domain.Decision, ttl time.Duration) error {
	s.setCalls++
	copyDecision := *decision
	s.lastDecision = &copyDecision
	s.lastTTL = ttl
	return nil
}

func (s *spyDecisionCache) Invalidate(context.Context, string, domain.ArtifactIdentity) error {
	return nil
}

func (s *spyDecisionCache) InvalidateTenant(context.Context, string) error {
	return nil
}

type spyProxyMetadataCache struct {
	getErr          error
	lastGetTenantID string
	lastGetArtifact domain.ArtifactIdentity
	setCalls        int
	lastSetTenantID string
	lastSetArtifact domain.ArtifactIdentity
	lastTTL         time.Duration
}

func newSpyProxyMetadataCache() *spyProxyMetadataCache {
	return &spyProxyMetadataCache{getErr: domain.ErrCacheMiss}
}

func (s *spyProxyMetadataCache) Get(_ context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	s.lastGetTenantID = tenantID
	s.lastGetArtifact = artifact
	return nil, s.getErr
}

func (s *spyProxyMetadataCache) Set(_ context.Context, tenantID string, artifact domain.ArtifactIdentity, _ *domain.ArtifactMetadata, ttl time.Duration) error {
	s.setCalls++
	s.lastSetTenantID = tenantID
	s.lastSetArtifact = artifact
	s.lastTTL = ttl
	return nil
}

type spyProxyEnricher struct {
	result       *domain.ArtifactMetadata
	err          error
	calls        int
	lastArtifact domain.ArtifactIdentity
}

func (s *spyProxyEnricher) Enrich(_ context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	s.calls++
	s.lastArtifact = artifact
	return s.result, s.err
}

type spyUpstreamClient struct {
	resolveDigest string
	resolveErr    error
	resolveCalls  int
	lastUpstream  domain.Upstream
	lastArtifact  domain.ArtifactIdentity
}

func (s *spyUpstreamClient) FetchMetadata(context.Context, domain.Upstream, domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	return nil, nil
}

func (s *spyUpstreamClient) FetchContent(context.Context, domain.Upstream, string) (*port.UpstreamResponse, error) {
	return nil, nil
}

func (s *spyUpstreamClient) ResolveReference(_ context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (string, error) {
	s.resolveCalls++
	s.lastUpstream = upstream
	s.lastArtifact = artifact
	return s.resolveDigest, s.resolveErr
}

type spyUpstreamRepository struct {
	upstream          *domain.Upstream
	err               error
	getByEcosystemHit int
	lastTenantID      string
	lastEcosystem     domain.EcosystemType
}

func (s *spyUpstreamRepository) GetByID(context.Context, string, string) (*domain.Upstream, error) {
	return nil, domain.ErrUpstreamNotFound
}

func (s *spyUpstreamRepository) GetByEcosystem(_ context.Context, tenantID string, ecosystem domain.EcosystemType) (*domain.Upstream, error) {
	s.getByEcosystemHit++
	s.lastTenantID = tenantID
	s.lastEcosystem = ecosystem
	if s.err != nil {
		return nil, s.err
	}
	return s.upstream, nil
}

func (s *spyUpstreamRepository) ListByTenant(context.Context, string) ([]domain.Upstream, error) {
	return nil, nil
}

func (s *spyUpstreamRepository) Create(context.Context, *domain.Upstream) error {
	return nil
}

func (s *spyUpstreamRepository) Update(context.Context, *domain.Upstream) error {
	return nil
}

func (s *spyUpstreamRepository) Delete(context.Context, string, string) error {
	return nil
}

func TestProxyService_Evaluate_SharedPolicyFlowAcrossEcosystems(t *testing.T) {
	t.Run("npm maximum age warn stays in core flow", func(t *testing.T) {
		timestamp := time.Now()
		publishedAt := timestamp.Add(-400 * 24 * time.Hour)

		policyRepo := &spyPolicyRepository{
			policies: []domain.Policy{
				{
					ID:       "p1",
					TenantID: "tenant-1",
					Name:     "block-old-warn",
					Type:     domain.PolicyTypeMaximumAge,
					Action:   domain.PolicyActionDeny,
					Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: proxyIntPtr(365), DryRun: true},
					Priority: 10,
					Enabled:  true,
				},
			},
		}
		decisionRepo := &spyDecisionRepository{}
		decisionCache := newSpyDecisionCache()
		metadataCache := newSpyProxyMetadataCache()
		enricher := &spyProxyEnricher{
			result: &domain.ArtifactMetadata{PublishedAt: &publishedAt},
		}

		enrichmentService := NewEnrichmentService(enricher, metadataCache, slog.New(slog.NewTextHandler(io.Discard, nil)))
		service := NewAccessService(
			policyRepo,
			decisionRepo,
			decisionCache,
			enrichmentService,
			policy.NewEvaluator(),
			&spyUpstreamClient{},
			&spyUpstreamRepository{err: domain.ErrUpstreamNotFound},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)

		decision, err := service.Evaluate(context.Background(), domain.AccessRequest{
			TenantID: "tenant-1",
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "Old-But-Stable",
				Version:   "1.0.0",
			},
			Timestamp: timestamp,
		})

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, domain.DecisionAllow, decision.Outcome)
		assert.Equal(t, "old-but-stable", decision.Artifact.Name)
		assert.Len(t, decision.Warnings, 1)
		assert.Contains(t, decision.Warnings[0], "block-old-warn")
		assert.Contains(t, decision.Warnings[0], "maximum allowed is 365 days")
		assert.Equal(t, 1, policyRepo.listByTenantCalls)
		assert.Equal(t, "tenant-1", policyRepo.lastTenantID)
		assert.Equal(t, 1, enricher.calls)
		assert.Equal(t, "old-but-stable", enricher.lastArtifact.Name)
		assert.Equal(t, domain.EcosystemNPM, enricher.lastArtifact.Ecosystem)
		assert.Equal(t, 1, metadataCache.setCalls)
		assert.Equal(t, "old-but-stable", metadataCache.lastSetArtifact.Name)
		assert.Equal(t, 1, decisionCache.setCalls)
		require.NotNil(t, decisionCache.lastDecision)
		assert.NotEmpty(t, decision.PolicyHash)
		assert.Equal(t, decision.PolicyHash, decisionCache.lastDecision.PolicyHash)
		assert.Equal(t, decision.Outcome, decisionCache.lastDecision.Outcome)
		assert.Equal(t, 1, decisionRepo.recordCalls)
		require.Len(t, decisionRepo.recorded, 1)
		assert.Equal(t, decision.PolicyHash, decisionRepo.recorded[0].PolicyHash)
		assert.Equal(t, decision.Warnings, decisionRepo.recorded[0].Warnings)
	})

	t.Run("oci mutable tag deny uses the same core evaluator", func(t *testing.T) {
		policyRepo := &spyPolicyRepository{
			policies: []domain.Policy{
				{
					ID:       "p2",
					TenantID: "tenant-1",
					Name:     "block-latest-tag",
					Type:     domain.PolicyTypeBlockMutableTag,
					Action:   domain.PolicyActionDeny,
					Config:   &domain.BlockMutableTagPolicyConfig{Tags: []string{"latest"}},
					Priority: 15,
					Enabled:  true,
				},
			},
		}
		decisionRepo := &spyDecisionRepository{}
		decisionCache := newSpyDecisionCache()
		metadataCache := newSpyProxyMetadataCache()
		enricher := &spyProxyEnricher{}
		upstreamClient := &spyUpstreamClient{resolveDigest: "sha256:deadbeef"}
		upstreamRepo := &spyUpstreamRepository{
			upstream: &domain.Upstream{
				ID:        "up-1",
				TenantID:  "tenant-1",
				Name:      "ghcr",
				Ecosystem: domain.EcosystemOCI,
				BaseURL:   "https://ghcr.io",
			},
		}

		enrichmentService := NewEnrichmentService(enricher, metadataCache, slog.New(slog.NewTextHandler(io.Discard, nil)))
		service := NewAccessService(
			policyRepo,
			decisionRepo,
			decisionCache,
			enrichmentService,
			policy.NewEvaluator(),
			upstreamClient,
			upstreamRepo,
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)

		decision, err := service.Evaluate(context.Background(), domain.AccessRequest{
			TenantID: "tenant-1",
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemOCI,
				Namespace: "GHCR.IO/Team",
				Name:      "My-App",
				Version:   "latest",
			},
			Timestamp: time.Now(),
		})

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, domain.DecisionDeny, decision.Outcome)
		assert.Contains(t, decision.Reason, `mutable tag "latest" is blocked`)
		assert.Equal(t, "ghcr.io/team", decision.Artifact.Namespace)
		assert.Equal(t, "my-app", decision.Artifact.Name)
		assert.Equal(t, "sha256:deadbeef", decision.Artifact.Digest)
		assert.Equal(t, 1, upstreamRepo.getByEcosystemHit)
		assert.Equal(t, domain.EcosystemOCI, upstreamRepo.lastEcosystem)
		assert.Equal(t, 1, upstreamClient.resolveCalls)
		assert.Equal(t, "ghcr.io/team", upstreamClient.lastArtifact.Namespace)
		assert.Equal(t, "my-app", upstreamClient.lastArtifact.Name)
		assert.Equal(t, "latest", upstreamClient.lastArtifact.Version)
		assert.Equal(t, 1, enricher.calls)
		assert.Equal(t, "sha256:deadbeef", enricher.lastArtifact.Digest)
		assert.Zero(t, metadataCache.setCalls)
		assert.Equal(t, 1, decisionCache.setCalls)
		assert.Equal(t, immutableDecisionTTL, decisionCache.lastTTL)
		assert.NotEmpty(t, decision.PolicyHash)
		assert.Equal(t, decision.PolicyHash, decisionCache.lastDecision.PolicyHash)
		assert.Equal(t, 1, decisionRepo.recordCalls)
		require.Len(t, decisionRepo.recorded, 1)
		assert.Equal(t, decision.PolicyHash, decisionRepo.recorded[0].PolicyHash)
		assert.Equal(t, decision.Reason, decisionRepo.recorded[0].Reason)
	})

	t.Run("npm license deny uses shared enrichment metadata", func(t *testing.T) {
		policyRepo := &spyPolicyRepository{
			policies: []domain.Policy{
				{
					ID:       "p3",
					TenantID: "tenant-1",
					Name:     "block-copyleft",
					Type:     domain.PolicyTypeLicense,
					Action:   domain.PolicyActionDeny,
					Config:   &domain.LicensePolicyConfig{Licenses: []string{"GPL-3.0-only"}},
					Priority: 10,
					Enabled:  true,
				},
			},
		}
		decisionRepo := &spyDecisionRepository{}
		decisionCache := newSpyDecisionCache()
		metadataCache := newSpyProxyMetadataCache()
		enricher := &spyProxyEnricher{
			result: &domain.ArtifactMetadata{
				Licenses: []string{"GPL-3.0-only"},
			},
		}

		enrichmentService := NewEnrichmentService(enricher, metadataCache, slog.New(slog.NewTextHandler(io.Discard, nil)))
		service := NewAccessService(
			policyRepo,
			decisionRepo,
			decisionCache,
			enrichmentService,
			policy.NewEvaluator(),
			&spyUpstreamClient{},
			&spyUpstreamRepository{err: domain.ErrUpstreamNotFound},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)

		decision, err := service.Evaluate(context.Background(), domain.AccessRequest{
			TenantID: "tenant-1",
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "copyleft-package",
				Version:   "1.0.0",
			},
			Timestamp: time.Now(),
		})

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, domain.DecisionDeny, decision.Outcome)
		assert.Contains(t, decision.Reason, `license "GPL-3.0-only"`)
		assert.Equal(t, 1, enricher.calls)
		assert.Equal(t, 1, decisionRepo.recordCalls)
		assert.Equal(t, decision.PolicyHash, decisionRepo.recorded[0].PolicyHash)
	})

	t.Run("npm license allowlist denies missing license metadata", func(t *testing.T) {
		policyRepo := &spyPolicyRepository{
			policies: []domain.Policy{
				{
					ID:       "p4",
					TenantID: "tenant-1",
					Name:     "allow-approved-licenses",
					Type:     domain.PolicyTypeLicenseAllowlist,
					Action:   domain.PolicyActionDeny,
					Config:   &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT", "Apache-2.0"}},
					Priority: 10,
					Enabled:  true,
				},
			},
		}
		decisionRepo := &spyDecisionRepository{}
		decisionCache := newSpyDecisionCache()
		metadataCache := newSpyProxyMetadataCache()
		enricher := &spyProxyEnricher{
			result: &domain.ArtifactMetadata{},
		}

		enrichmentService := NewEnrichmentService(enricher, metadataCache, slog.New(slog.NewTextHandler(io.Discard, nil)))
		service := NewAccessService(
			policyRepo,
			decisionRepo,
			decisionCache,
			enrichmentService,
			policy.NewEvaluator(),
			&spyUpstreamClient{},
			&spyUpstreamRepository{err: domain.ErrUpstreamNotFound},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)

		decision, err := service.Evaluate(context.Background(), domain.AccessRequest{
			TenantID: "tenant-1",
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "unknown-license-package",
				Version:   "1.0.0",
			},
			Timestamp: time.Now(),
		})

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, domain.DecisionDeny, decision.Outcome)
		assert.Contains(t, decision.Reason, "license metadata is unavailable")
		assert.Equal(t, 1, enricher.calls)
		assert.Equal(t, 1, decisionRepo.recordCalls)
	})

	t.Run("invalid stored policy fails closed", func(t *testing.T) {
		policyRepo := &spyPolicyRepository{
			policies: []domain.Policy{
				{
					ID:       "p-invalid",
					TenantID: "tenant-1",
					Name:     "broken-policy",
					Type:     domain.PolicyTypeCVSSThreshold,
					Action:   domain.PolicyActionDeny,
					Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}},
					Priority: 10,
					Enabled:  true,
				},
			},
		}
		decisionRepo := &spyDecisionRepository{}
		decisionCache := newSpyDecisionCache()
		metadataCache := newSpyProxyMetadataCache()
		enricher := &spyProxyEnricher{}

		enrichmentService := NewEnrichmentService(enricher, metadataCache, slog.New(slog.NewTextHandler(io.Discard, nil)))
		service := NewAccessService(
			policyRepo,
			decisionRepo,
			decisionCache,
			enrichmentService,
			policy.NewEvaluator(),
			&spyUpstreamClient{},
			&spyUpstreamRepository{err: domain.ErrUpstreamNotFound},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)

		decision, err := service.Evaluate(context.Background(), domain.AccessRequest{
			TenantID: "tenant-1",
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "safe-package",
				Version:   "1.0.0",
			},
			Timestamp: time.Now(),
		})

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, domain.DecisionDeny, decision.Outcome)
		assert.Equal(t, "invalid policy configuration", decision.Reason)
		require.Len(t, decision.Reasons, 1)
		assert.Equal(t, domain.ReasonCategoryEvaluationError, decision.Reasons[0].Category)
		assert.Equal(t, 1, decisionRepo.recordCalls)
		assert.Equal(t, 1, decisionCache.setCalls)
	})

	t.Run("deprecated stored policy config fails closed", func(t *testing.T) {
		policyRepo := &spyPolicyRepository{listErr: domain.ErrDeprecatedPolicyConfig}
		decisionRepo := &spyDecisionRepository{}
		decisionCache := newSpyDecisionCache()
		enricher := &spyProxyEnricher{}
		metadataCache := newSpyProxyMetadataCache()
		enrichmentService := NewEnrichmentService(enricher, metadataCache, slog.New(slog.NewTextHandler(io.Discard, nil)))
		service := NewAccessService(
			policyRepo,
			decisionRepo,
			decisionCache,
			enrichmentService,
			policy.NewEvaluator(),
			&spyUpstreamClient{},
			&spyUpstreamRepository{err: domain.ErrUpstreamNotFound},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)

		decision, err := service.Evaluate(context.Background(), domain.AccessRequest{
			TenantID: "tenant-1",
			Artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "safe-package",
				Version:   "1.0.0",
			},
			Timestamp: time.Now(),
		})

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, domain.DecisionDeny, decision.Outcome)
		assert.Equal(t, "invalid policy configuration", decision.Reason)
		require.Len(t, decision.Reasons, 1)
		assert.Contains(t, decision.Reasons[0].Message, "deprecated stored policy config")
		assert.Equal(t, 1, decisionRepo.recordCalls)
		assert.Equal(t, 1, decisionCache.setCalls)
	})
}
