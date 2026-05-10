package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type staticMetadataCache struct {
	getErr error
}

func (s staticMetadataCache) Get(context.Context, string, domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	return nil, s.getErr
}

func (s staticMetadataCache) Set(context.Context, string, domain.ArtifactIdentity, *domain.ArtifactMetadata, time.Duration) error {
	return nil
}

func (s staticMetadataCache) InvalidateTenant(context.Context, string) error {
	return nil
}

func TestIsExpectedSpanOutcome(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "cache miss",
			err:  domain.ErrCacheMiss,
			want: true,
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: true,
		},
		{
			name: "wrapped artifact not found",
			err:  fmt.Errorf("resolving artifact: %w", domain.ErrArtifactNotFound),
			want: true,
		},
		{
			name: "policy not found",
			err:  domain.ErrPolicyNotFound,
			want: true,
		},
		{
			name: "tenant name conflict",
			err:  domain.ErrTenantNameConflict,
			want: true,
		},
		{
			name: "upstream conflict",
			err:  domain.ErrUpstreamPolicyConflict,
			want: true,
		},
		{
			name: "invalid policy",
			err:  domain.ErrInvalidPolicy,
			want: true,
		},
		{
			name: "enrichment failed",
			err:  domain.ErrEnrichmentFailed,
			want: false,
		},
		{
			name: "audit unavailable",
			err:  domain.ErrAuditUnavailable,
			want: false,
		},
		{
			name: "bundle unavailable",
			err:  domain.ErrBundleUnavailable,
			want: false,
		},
		{
			name: "upstream unavailable",
			err:  domain.ErrUpstreamUnavailable,
			want: false,
		},
		{
			name: "deprecated policy config",
			err:  domain.ErrDeprecatedPolicyConfig,
			want: false,
		},
		{
			name: "unsupported policy schema version",
			err:  domain.ErrUnsupportedPolicySchemaVersion,
			want: false,
		},
		{
			name: "invalid artifact reference",
			err:  domain.ErrInvalidArtifactRef,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isExpectedSpanOutcome(tt.err))
		})
	}
}

func TestEnrichmentService_MetadataCacheLookupSpanStatus(t *testing.T) {
	tests := []struct {
		name       string
		cacheErr   error
		wantStatus codes.Code
	}{
		{
			name:       "cache miss remains unset",
			cacheErr:   domain.ErrCacheMiss,
			wantStatus: codes.Unset,
		},
		{
			name:       "backend failure is error",
			cacheErr:   errors.New("cache backend unavailable"),
			wantStatus: codes.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter, provider := setupServiceTracing(t)
			artifact := domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "lodash",
				Version:   "4.17.21",
			}
			enricher := &mockEnricher{result: &domain.ArtifactMetadata{}}
			service := NewEnrichmentService(
				enricher,
				staticMetadataCache{getErr: tt.cacheErr},
				slog.New(slog.NewTextHandler(io.Discard, nil)),
			)

			_, err := service.Enrich(context.Background(), "tenant-1", artifact)

			require.NoError(t, err)
			require.NoError(t, provider.ForceFlush(context.Background()))
			span := firstServiceSpanNamed(t, exporter.GetSpans().Snapshots(), "enrichment.metadata_cache_lookup")
			assert.Equal(t, tt.wantStatus, span.Status().Code)
		})
	}
}

func TestAccessService_DecisionCacheLookupSpanStatus(t *testing.T) {
	tests := []struct {
		name       string
		cacheErr   error
		wantStatus codes.Code
	}{
		{
			name:       "cache miss remains unset",
			cacheErr:   domain.ErrCacheMiss,
			wantStatus: codes.Unset,
		},
		{
			name:       "backend failure is error",
			cacheErr:   errors.New("cache backend unavailable"),
			wantStatus: codes.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter, provider := setupServiceTracing(t)
			decisionCache := &spyDecisionCache{getErr: tt.cacheErr}
			service := NewAccessService(
				&spyPolicyRepository{},
				&spyDecisionRepository{},
				decisionCache,
				nil,
				policy.NewEvaluator(),
				&spyUpstreamClient{},
				&spyUpstreamRepository{},
				slog.New(slog.NewTextHandler(io.Discard, nil)),
			)
			req := domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "lodash",
					Version:   "4.17.21",
				},
			}

			_, err := service.Evaluate(context.Background(), req)

			require.NoError(t, err)
			require.NoError(t, provider.ForceFlush(context.Background()))
			span := firstServiceSpanNamed(t, exporter.GetSpans().Snapshots(), "access.decision_cache_lookup")
			assert.Equal(t, tt.wantStatus, span.Status().Code)
		})
	}
}

func setupServiceTracing(t *testing.T) (*tracetest.InMemoryExporter, *sdktrace.TracerProvider) {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(exporter),
	)
	previousProvider := otel.GetTracerProvider()
	previousTracer := tracer
	otel.SetTracerProvider(provider)
	tracer = provider.Tracer("github.com/danielterry/dependency-firewall/internal/core/service")
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(context.Background()))
		otel.SetTracerProvider(previousProvider)
		tracer = previousTracer
	})
	return exporter, provider
}

func firstServiceSpanNamed(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	for _, span := range spans {
		if span.Name() == name {
			return span
		}
	}

	t.Fatalf("span %q not found", name)
	return nil
}
