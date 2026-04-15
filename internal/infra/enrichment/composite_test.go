package enrichment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type mockEnricher struct {
	meta *domain.ArtifactMetadata
	err  error
}

func (m *mockEnricher) Enrich(ctx context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	return m.meta, m.err
}

func TestCompositeEnricher_Enrich(t *testing.T) {
	ctx := context.Background()
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "test-pkg",
		Version:   "1.0.0",
	}

	t.Run("merges metadata from multiple enrichers", func(t *testing.T) {
		now := time.Now()
		cvss := 7.5

		e1 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				PublishedAt: &now,
			},
		}
		e2 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				MaxCVSS: &cvss,
				Vulnerabilities: []domain.Vulnerability{
					{ID: "CVE-2023-1234", CVSS: 7.5},
				},
			},
		}

		composite := NewCompositeEnricher(e1, e2)
		meta, err := composite.Enrich(ctx, artifact)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if meta.PublishedAt == nil || !meta.PublishedAt.Equal(now) {
			t.Errorf("PublishedAt not merged correctly")
		}
		if meta.MaxCVSS == nil || *meta.MaxCVSS != cvss {
			t.Errorf("MaxCVSS not merged correctly")
		}
		if len(meta.Vulnerabilities) != 1 {
			t.Errorf("Vulnerabilities not merged correctly")
		}
	})

	t.Run("returns error if any enricher fails", func(t *testing.T) {
		e1 := &mockEnricher{
			meta: &domain.ArtifactMetadata{},
		}
		e2 := &mockEnricher{
			err: errors.New("enrichment failed"),
		}

		composite := NewCompositeEnricher(e1, e2)
		_, err := composite.Enrich(ctx, artifact)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("handles nil metadata from enrichers", func(t *testing.T) {
		e1 := &mockEnricher{
			meta: nil,
		}
		e2 := &mockEnricher{
			meta: &domain.ArtifactMetadata{},
		}

		composite := NewCompositeEnricher(e1, e2)
		meta, err := composite.Enrich(ctx, artifact)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if meta == nil {
			t.Fatal("expected metadata, got nil")
		}
	})

	t.Run("works with no enrichers", func(t *testing.T) {
		composite := NewCompositeEnricher()
		meta, err := composite.Enrich(ctx, artifact)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if meta == nil {
			t.Fatal("expected empty metadata, got nil")
		}
	})

	t.Run("later enrichers override earlier ones", func(t *testing.T) {
		early := time.Now().Add(-24 * time.Hour)
		late := time.Now()

		e1 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				PublishedAt: &early,
			},
		}
		e2 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				PublishedAt: &late,
			},
		}

		composite := NewCompositeEnricher(e1, e2)
		meta, err := composite.Enrich(ctx, artifact)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if meta.PublishedAt == nil || !meta.PublishedAt.Equal(late) {
			t.Errorf("expected later PublishedAt to override, got %v", meta.PublishedAt)
		}
	})

	t.Run("appends vulnerabilities from multiple enrichers", func(t *testing.T) {
		e1 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				Vulnerabilities: []domain.Vulnerability{
					{ID: "CVE-2023-1111"},
				},
			},
		}
		e2 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				Vulnerabilities: []domain.Vulnerability{
					{ID: "CVE-2023-2222"},
				},
			},
		}

		composite := NewCompositeEnricher(e1, e2)
		meta, err := composite.Enrich(ctx, artifact)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(meta.Vulnerabilities) != 2 {
			t.Errorf("expected 2 vulnerabilities, got %d", len(meta.Vulnerabilities))
		}
	})

	t.Run("sets IsMutableTag if any enricher sets it", func(t *testing.T) {
		e1 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				IsMutableTag: false,
			},
		}
		e2 := &mockEnricher{
			meta: &domain.ArtifactMetadata{
				IsMutableTag: true,
			},
		}

		composite := NewCompositeEnricher(e1, e2)
		meta, err := composite.Enrich(ctx, artifact)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !meta.IsMutableTag {
			t.Error("expected IsMutableTag to be true")
		}
	})
}
