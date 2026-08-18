//go:build integration

package valkey

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	valkeygo "github.com/valkey-io/valkey-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestConnect_realValkeyEmitsOpenTelemetrySpans(t *testing.T) {
	ctx := context.Background()
	exporter := tracetest.NewInMemoryExporter()
	provider := tracesdk.NewTracerProvider(
		tracesdk.WithSampler(tracesdk.AlwaysSample()),
		tracesdk.WithSyncer(exporter),
	)
	previousProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		require.NoError(t, provider.Shutdown(context.Background()))
		otel.SetTracerProvider(previousProvider)
	})

	client := newIntegrationClient(t, ctx)

	cache := NewDecisionCache(client)
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "express",
		Version:   "4.19.1",
	}
	decision := &domain.Decision{
		TenantID: "tenant-1",
		Artifact: artifact,
		Outcome:  domain.DecisionAllow,
	}

	operationCtx, rootSpan := provider.Tracer("integration-test").Start(ctx, "root")
	require.NoError(t, HealthCheck(operationCtx, client))
	require.NoError(t, cache.Set(operationCtx, decision, time.Minute))
	cached, err := cache.Get(operationCtx, decision.TenantID, artifact)
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, domain.DecisionAllow, cached.Outcome)
	require.NoError(t, cache.InvalidateTenant(operationCtx, decision.TenantID))
	rootSpan.End()

	require.NoError(t, provider.ForceFlush(ctx))

	spans := exporter.GetSpans().Snapshots()
	require.NotEmpty(t, spans)

	expectedNames := []string{"valkey.dial", "PING", "GET", "SET", "INCR"}
	for _, name := range expectedNames {
		assert.Truef(t, hasSpanNamed(spans, name), "missing span %q, got spans %v", name, spanNames(spans))
	}

	rootTraceID := rootSpan.SpanContext().TraceID()

	dialSpan := firstSpanNamed(t, spans, "valkey.dial")
	assert.Equal(t, codes.Ok, dialSpan.Status().Code)
	assertSpanAttributeEquals(t, dialSpan, "db.system", "valkey")
	assertSpanHasAttribute(t, dialSpan, "server.address")
	assertSpanHasAttribute(t, dialSpan, "server.port")

	for _, name := range []string{"PING", "GET", "SET", "INCR"} {
		span := firstSpanNamed(t, spans, name)
		assert.Equal(t, rootTraceID, span.SpanContext().TraceID())
		assert.Equal(t, rootSpan.SpanContext().SpanID(), span.Parent().SpanID())
		assert.Equal(t, codes.Ok, span.Status().Code)
		assertSpanAttributeEquals(t, span, "db.system", "valkey")
		assertSpanAttributeEquals(t, span, "db.operation", name)
		assertSpanAttributePositiveInt(t, span, "db.stmt_size")
		assertSpanHasNoAttribute(t, span, "db.statement")
	}
}

func TestDecisionCache_realValkey(t *testing.T) {
	ctx := context.Background()
	client := newIntegrationClient(t, ctx)

	cache := NewDecisionCache(client)

	t.Run("set get round trip", func(t *testing.T) {
		decision := testDecision("tenant-round-trip", domain.DecisionAllow)

		require.NoError(t, cache.Set(ctx, decision, time.Minute))

		cached, err := cache.Get(ctx, decision.TenantID, decision.Artifact)
		require.NoError(t, err)
		require.NotNil(t, cached)
		assert.Equal(t, decision, cached)
	})

	t.Run("miss returns cache miss", func(t *testing.T) {
		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "missing-package",
			Version:   "1.0.0",
		}

		_, err := cache.Get(ctx, "tenant-miss", artifact, "")
		require.ErrorIs(t, err, domain.ErrCacheMiss)
	})

	t.Run("invalidate removes cached decision", func(t *testing.T) {
		decision := testDecision("tenant-invalidate", domain.DecisionAllow)

		require.NoError(t, cache.Set(ctx, decision, time.Minute))
		require.NoError(t, cache.Invalidate(ctx, decision.TenantID, decision.Artifact))

		_, err := cache.Get(ctx, decision.TenantID, decision.Artifact)
		require.ErrorIs(t, err, domain.ErrCacheMiss)
	})

	t.Run("tenant invalidation bumps generation without affecting other tenants", func(t *testing.T) {
		tenantOneDecision := testDecision("tenant-generation-one", domain.DecisionAllow)
		tenantTwoDecision := testDecision("tenant-generation-two", domain.DecisionDeny)

		require.NoError(t, cache.Set(ctx, tenantOneDecision, time.Minute))
		require.NoError(t, cache.Set(ctx, tenantTwoDecision, time.Minute))

		generationBefore, err := cache.currentGeneration(ctx, tenantOneDecision.TenantID)
		require.NoError(t, err)
		assert.Equal(t, int64(0), generationBefore)

		require.NoError(t, cache.InvalidateTenant(ctx, tenantOneDecision.TenantID))

		generationAfter, err := cache.currentGeneration(ctx, tenantOneDecision.TenantID)
		require.NoError(t, err)
		assert.Equal(t, int64(1), generationAfter)

		_, err = cache.Get(ctx, tenantOneDecision.TenantID, tenantOneDecision.Artifact)
		require.ErrorIs(t, err, domain.ErrCacheMiss)

		cachedOtherTenant, err := cache.Get(ctx, tenantTwoDecision.TenantID, tenantTwoDecision.Artifact)
		require.NoError(t, err)
		require.NotNil(t, cachedOtherTenant)
		assert.Equal(t, tenantTwoDecision, cachedOtherTenant)

		reloadedDecision := testDecision(tenantOneDecision.TenantID, domain.DecisionDeny)
		require.NoError(t, cache.Set(ctx, reloadedDecision, time.Minute))

		cachedReloaded, err := cache.Get(ctx, reloadedDecision.TenantID, reloadedDecision.Artifact)
		require.NoError(t, err)
		require.NotNil(t, cachedReloaded)
		assert.Equal(t, reloadedDecision, cachedReloaded)
	})

	t.Run("ttl expiry returns cache miss", func(t *testing.T) {
		decision := testDecision("tenant-expiry", domain.DecisionAllow)

		require.NoError(t, cache.Set(ctx, decision, 150*time.Millisecond))

		cached, err := cache.Get(ctx, decision.TenantID, decision.Artifact)
		require.NoError(t, err)
		require.NotNil(t, cached)

		require.Eventually(t, func() bool {
			_, err := cache.Get(ctx, decision.TenantID, decision.Artifact)
			return err == domain.ErrCacheMiss
		}, 3*time.Second, 25*time.Millisecond)
	})
}

func TestMetadataCache_realValkey(t *testing.T) {
	ctx := context.Background()
	client := newIntegrationClient(t, ctx)

	require.NoError(t, HealthCheck(ctx, client))

	cache := NewMetadataCache(client)

	t.Run("get returns cache miss when metadata is absent", func(t *testing.T) {
		_, err := cache.Get(ctx, "tenant-miss", domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "left-pad",
			Version:   "1.3.0",
		})
		require.ErrorIs(t, err, domain.ErrCacheMiss)
	})

	t.Run("set and get round trip metadata", func(t *testing.T) {
		publishedAt := time.Unix(1_700_000_000, 0).UTC()
		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Namespace: "library",
			Name:      "alpine",
			Digest:    "sha256:0123456789abcdef",
		}
		metadata := &domain.ArtifactMetadata{
			PublishedAt: &publishedAt,
			MaxCVSS:     ptrFloat64(9.8),
			Licenses:    []string{"MIT", "Apache-2.0"},
			Vulnerabilities: []domain.Vulnerability{{
				ID:       "OSV-2024-123",
				Severity: "HIGH",
				CVSS:     9.8,
				Summary:  "critical vulnerability",
			}},
			IsMutableTag: false,
			SourceRepository: &domain.SourceRepository{
				Host:  "github.com",
				Owner: "library",
				Repo:  "alpine",
			},
			Scorecard: &domain.ScorecardResult{
				Score: ptrFloat64(8.7),
				Checks: map[string]float64{
					"binary-artifacts": 10,
				},
			},
		}

		require.NoError(t, cache.Set(ctx, "tenant-round-trip", artifact, metadata, time.Minute))

		cached, err := cache.Get(ctx, "tenant-round-trip", artifact, "")
		require.NoError(t, err)
		require.NotNil(t, cached)
		require.NotNil(t, cached.PublishedAt)
		require.NotNil(t, cached.MaxCVSS)
		assert.True(t, publishedAt.Equal(*cached.PublishedAt))
		assert.InDelta(t, 9.8, *cached.MaxCVSS, 0.001)
		assert.Equal(t, metadata.Licenses, cached.Licenses)
		assert.Equal(t, metadata.Vulnerabilities, cached.Vulnerabilities)
		assert.Equal(t, metadata.IsMutableTag, cached.IsMutableTag)
		require.NotNil(t, cached.SourceRepository)
		assert.Equal(t, metadata.SourceRepository.ProjectURI(), cached.SourceRepository.ProjectURI())
		require.NotNil(t, cached.Scorecard)
		require.NotNil(t, cached.Scorecard.Score)
		assert.InDelta(t, 8.7, *cached.Scorecard.Score, 0.001)
		assert.Equal(t, metadata.Scorecard.Checks, cached.Scorecard.Checks)
	})

	t.Run("invalidate tenant hides prior generation and allows repopulation", func(t *testing.T) {
		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "lodash",
			Version:   "4.17.21",
		}
		firstMetadata := &domain.ArtifactMetadata{MaxCVSS: ptrFloat64(7.2)}
		secondMetadata := &domain.ArtifactMetadata{MaxCVSS: ptrFloat64(3.1)}

		require.NoError(t, cache.Set(ctx, "tenant-generation", artifact, firstMetadata, time.Minute))

		cached, err := cache.Get(ctx, "tenant-generation", artifact, "")
		require.NoError(t, err)
		require.NotNil(t, cached)
		require.NotNil(t, cached.MaxCVSS)
		assert.InDelta(t, 7.2, *cached.MaxCVSS, 0.001)

		require.NoError(t, cache.InvalidateTenant(ctx, "tenant-generation"))

		_, err = cache.Get(ctx, "tenant-generation", artifact, "")
		require.ErrorIs(t, err, domain.ErrCacheMiss)

		require.NoError(t, cache.Set(ctx, "tenant-generation", artifact, secondMetadata, time.Minute))

		cached, err = cache.Get(ctx, "tenant-generation", artifact, "")
		require.NoError(t, err)
		require.NotNil(t, cached)
		require.NotNil(t, cached.MaxCVSS)
		assert.InDelta(t, 3.1, *cached.MaxCVSS, 0.001)
	})

	t.Run("ttl expiry evicts metadata", func(t *testing.T) {
		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "chalk",
			Version:   "5.4.1",
		}

		require.NoError(
			t,
			cache.Set(
				ctx,
				"tenant-ttl",
				artifact,
				&domain.ArtifactMetadata{MaxCVSS: ptrFloat64(5.5)},
				200*time.Millisecond,
			),
		)

		require.Eventually(t, func() bool {
			_, err := cache.Get(ctx, "tenant-ttl", artifact, "")
			return err != nil && err == domain.ErrCacheMiss
		}, 5*time.Second, 25*time.Millisecond)
	})
}

func newIntegrationClient(t *testing.T, ctx context.Context) valkeygo.Client {
	t.Helper()

	client, err := Connect(ctx, config.ValkeyConfig{Addr: startValkeyContainer(t)})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})

	return client
}

func startValkeyContainer(t *testing.T) string {
	t.Helper()

	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "valkey/valkey:8-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor: wait.ForListeningPort("6379/tcp").
				WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, container.Terminate(ctx))
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)

	return net.JoinHostPort(host, port.Port())
}

func hasSpanNamed(spans []tracesdk.ReadOnlySpan, name string) bool {
	return slices.ContainsFunc(spans, func(span tracesdk.ReadOnlySpan) bool {
		return span.Name() == name
	})
}

func firstSpanNamed(t *testing.T, spans []tracesdk.ReadOnlySpan, name string) tracesdk.ReadOnlySpan {
	t.Helper()

	for _, span := range spans {
		if span.Name() == name {
			return span
		}
	}

	t.Fatalf("span %q not found in %v", name, spanNames(spans))
	return nil
}

func spanNames(spans []tracesdk.ReadOnlySpan) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Name())
	}
	return names
}

func assertSpanAttributeEquals(t *testing.T, span tracesdk.ReadOnlySpan, key attribute.Key, want any) {
	t.Helper()

	for _, attr := range span.Attributes() {
		if attr.Key != key {
			continue
		}
		assert.Equal(t, want, attr.Value.AsInterface())
		return
	}

	t.Fatalf("attribute %q not found on span %q", key, span.Name())
}

func assertSpanHasAttribute(t *testing.T, span tracesdk.ReadOnlySpan, key attribute.Key) {
	t.Helper()

	for _, attr := range span.Attributes() {
		if attr.Key == key {
			return
		}
	}

	t.Fatalf("attribute %q not found on span %q", key, span.Name())
}

func assertSpanHasNoAttribute(t *testing.T, span tracesdk.ReadOnlySpan, key attribute.Key) {
	t.Helper()

	for _, attr := range span.Attributes() {
		if attr.Key == key {
			t.Fatalf("attribute %q unexpectedly present on span %q", key, span.Name())
		}
	}
}

func assertSpanAttributePositiveInt(t *testing.T, span tracesdk.ReadOnlySpan, key attribute.Key) {
	t.Helper()

	for _, attr := range span.Attributes() {
		if attr.Key != key {
			continue
		}

		value, ok := attr.Value.AsInterface().(int64)
		require.Truef(t, ok, "attribute %q on span %q is not an int64", key, span.Name())
		assert.Greater(t, value, int64(0))
		return
	}

	t.Fatalf("attribute %q not found on span %q", key, span.Name())
}

func testDecision(tenantID string, outcome domain.DecisionOutcome) *domain.Decision {
	cachedAt := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	userReason := "allowed for test coverage"
	action := domain.PolicyActionAllow
	reasonMessage := "matched allow policy"

	if outcome == domain.DecisionDeny {
		userReason = "denied for test coverage"
		action = domain.PolicyActionDeny
		reasonMessage = "matched deny policy"
	}

	return &domain.Decision{
		ID:       "decision-" + tenantID,
		TenantID: tenantID,
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "@acme",
			Name:      "widget",
			Version:   "1.2.3",
		},
		Outcome:    outcome,
		PolicyID:   "policy-" + tenantID,
		PolicyHash: "hash-" + tenantID,
		Reason:     userReason,
		Reasons: []domain.EvaluationReason{
			{
				PolicyID:   "policy-" + tenantID,
				PolicyName: "test-policy",
				Category:   domain.ReasonPolicyMatch,
				Action:     action,
				Message:    reasonMessage,
			},
		},
		Warnings:    []string{"cached warning"},
		CachedAt:    &cachedAt,
		EvaluatedAt: time.Date(2024, time.January, 2, 3, 5, 5, 0, time.UTC),
	}
}

func ptrFloat64(v float64) *float64 {
	return &v
}
