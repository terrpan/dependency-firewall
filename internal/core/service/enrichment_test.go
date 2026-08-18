package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// --- mock enricher ---

type mockEnricher struct {
	result *domain.ArtifactMetadata
	err    error
	calls  int
}

func (m *mockEnricher) Enrich(_ context.Context, _ domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	m.calls++
	return m.result, m.err
}

// --- mock metadata cache ---

type mockMetadataCache struct {
	store    map[string]*domain.ArtifactMetadata
	setCalls int
	lastTTL  time.Duration
}

func newMockMetadataCache() *mockMetadataCache {
	return &mockMetadataCache{store: make(map[string]*domain.ArtifactMetadata)}
}

func (m *mockMetadataCache) cacheKey(tenantID string, artifact domain.ArtifactIdentity) string {
	return tenantID + ":" + string(artifact.Ecosystem) + ":" + artifact.Name + ":" + artifact.Version
}

func (m *mockMetadataCache) Get(
	_ context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
) (*domain.ArtifactMetadata, error) {
	key := m.cacheKey(tenantID, artifact)
	if meta, ok := m.store[key]; ok {
		return meta, nil
	}
	return nil, domain.ErrCacheMiss
}

func (m *mockMetadataCache) Set(
	_ context.Context,
	tenantID string,
	artifact domain.ArtifactIdentity,
	metadata *domain.ArtifactMetadata,
	ttl time.Duration,
) error {
	m.setCalls++
	m.lastTTL = ttl
	key := m.cacheKey(tenantID, artifact)
	m.store[key] = metadata
	return nil
}

func (m *mockMetadataCache) InvalidateTenant(_ context.Context, tenantID string) error {
	for key := range m.store {
		if strings.HasPrefix(key, tenantID+":") {
			delete(m.store, key)
		}
	}
	return nil
}

func TestEnrichmentService_Enrich(t *testing.T) {
	logger := slog.Default()
	maxCVSS := 7.5
	testMetadata := &domain.ArtifactMetadata{
		MaxCVSS: &maxCVSS,
		Vulnerabilities: []domain.Vulnerability{
			{ID: "CVE-2024-001", Severity: "high", CVSS: 7.5, Summary: "test vuln"},
		},
	}

	npmArtifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.20",
	}

	digestArtifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.20",
		Digest:    "sha256:abc123",
	}

	t.Run("cache hit returns cached metadata without calling enricher", func(t *testing.T) {
		cache := newMockMetadataCache()
		key := cache.cacheKey("tenant-1", npmArtifact)
		cache.store[key] = testMetadata

		enricher := &mockEnricher{result: testMetadata}
		svc := NewEnrichmentService(enricher, cache, logger)

		result, err := svc.Enrich(context.Background(), "tenant-1", npmArtifact)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, testMetadata, result)
		assert.Equal(t, 0, enricher.calls)
	})

	t.Run("cache miss calls enricher and caches result", func(t *testing.T) {
		cache := newMockMetadataCache()
		enricher := &mockEnricher{result: testMetadata}
		svc := NewEnrichmentService(enricher, cache, logger)

		result, err := svc.Enrich(context.Background(), "tenant-1", npmArtifact)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, testMetadata, result)
		assert.Equal(t, 1, enricher.calls)
		assert.Equal(t, 1, cache.setCalls)
	})

	t.Run("enricher failure returns nil metadata (fail-open)", func(t *testing.T) {
		cache := newMockMetadataCache()
		enricher := &mockEnricher{err: errors.New("upstream down")}
		svc := NewEnrichmentService(enricher, cache, logger)

		result, err := svc.Enrich(context.Background(), "tenant-1", npmArtifact)

		require.NoError(t, err)
		assert.Nil(t, result)
		assert.Equal(t, 1, enricher.calls)
		assert.Equal(t, 0, cache.setCalls)
	})

	t.Run("mutable reference gets shorter cache TTL", func(t *testing.T) {
		cache := newMockMetadataCache()
		enricher := &mockEnricher{result: testMetadata}
		svc := NewEnrichmentService(enricher, cache, logger)

		_, err := svc.Enrich(context.Background(), "tenant-1", npmArtifact)

		require.NoError(t, err)
		assert.Equal(t, mutableRefTTL, cache.lastTTL)
	})

	t.Run("immutable reference (digest) gets longer cache TTL", func(t *testing.T) {
		cache := newMockMetadataCache()
		enricher := &mockEnricher{result: testMetadata}
		svc := NewEnrichmentService(enricher, cache, logger)

		_, err := svc.Enrich(context.Background(), "tenant-1", digestArtifact)

		require.NoError(t, err)
		assert.Equal(t, immutableRefTTL, cache.lastTTL)
	})
}
