package npm

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestMetadataEnricher_Enrich(t *testing.T) {
	logger := slog.Default()

	t.Run("successfully extracts PublishedAt for npm package", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/express" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"time": {
					"modified": "2024-03-20T15:53:05.388Z",
					"created": "2010-12-29T07:28:24.371Z",
					"4.17.1": "2019-05-25T23:58:54.329Z",
					"4.19.1": "2024-03-20T15:53:05.388Z"
				}
			}`))
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "4.19.1",
		}

		meta, err := enricher.Enrich(context.Background(), artifact)
		if err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}
		if meta == nil {
			t.Fatal("expected metadata, got nil")
		}
		if meta.PublishedAt == nil {
			t.Fatal("expected PublishedAt to be set")
		}

		expected := time.Date(2024, 3, 20, 15, 53, 5, 388000000, time.UTC)
		if !meta.PublishedAt.Equal(expected) {
			t.Errorf("PublishedAt = %v, want %v", meta.PublishedAt, expected)
		}
	})

	t.Run("successfully extracts PublishedAt for scoped package", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/@types/node" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"time": {
					"20.0.0": "2023-03-17T16:43:13.123Z"
				}
			}`))
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "@types",
			Name:      "node",
			Version:   "20.0.0",
		}

		meta, err := enricher.Enrich(context.Background(), artifact)
		if err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}
		if meta.PublishedAt == nil {
			t.Fatal("expected PublishedAt to be set")
		}

		expected := time.Date(2023, 3, 17, 16, 43, 13, 123000000, time.UTC)
		if !meta.PublishedAt.Equal(expected) {
			t.Errorf("PublishedAt = %v, want %v", meta.PublishedAt, expected)
		}
	})

	t.Run("returns empty metadata for non-npm ecosystem", func(t *testing.T) {
		enricher := NewMetadataEnricher(http.DefaultClient, logger)

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemOCI,
			Name:      "nginx",
			Version:   "latest",
		}

		meta, err := enricher.Enrich(context.Background(), artifact)
		if err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}
		if meta.PublishedAt != nil {
			t.Error("expected PublishedAt to be nil for non-npm ecosystem")
		}
	})

	t.Run("returns empty metadata when version is missing", func(t *testing.T) {
		enricher := NewMetadataEnricher(http.DefaultClient, logger)

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "",
		}

		meta, err := enricher.Enrich(context.Background(), artifact)
		if err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}
		if meta.PublishedAt != nil {
			t.Error("expected PublishedAt to be nil when version is missing")
		}
	})

	t.Run("returns empty metadata when package not found", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"Not found"}`))
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "nonexistent-pkg",
			Version:   "1.0.0",
		}

		meta, err := enricher.Enrich(context.Background(), artifact)
		if err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}
		if meta.PublishedAt != nil {
			t.Error("expected PublishedAt to be nil for nonexistent package")
		}
	})

	t.Run("returns error on rate limit", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "4.19.1",
		}

		_, err := enricher.Enrich(context.Background(), artifact)
		if err == nil {
			t.Fatal("expected error on rate limit, got nil")
		}
	})

	t.Run("returns error on server error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "4.19.1",
		}

		_, err := enricher.Enrich(context.Background(), artifact)
		if err == nil {
			t.Fatal("expected error on server error, got nil")
		}
	})

	t.Run("handles missing time field for version", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"time": {
					"1.0.0": "2020-01-01T00:00:00.000Z"
				}
			}`))
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "2.0.0",
		}

		meta, err := enricher.Enrich(context.Background(), artifact)
		if err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}
		if meta.PublishedAt != nil {
			t.Error("expected PublishedAt to be nil when version not in time map")
		}
	})

	t.Run("handles malformed JSON", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{invalid json`))
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		artifact := domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "4.19.1",
		}

		_, err := enricher.Enrich(context.Background(), artifact)
		if err == nil {
			t.Fatal("expected error on malformed JSON, got nil")
		}
	})
}

func TestBuildPackageName(t *testing.T) {
	tests := []struct {
		name     string
		artifact domain.ArtifactIdentity
		want     string
	}{
		{
			name: "unscoped package",
			artifact: domain.ArtifactIdentity{
				Name: "express",
			},
			want: "express",
		},
		{
			name: "scoped package",
			artifact: domain.ArtifactIdentity{
				Namespace: "@types",
				Name:      "node",
			},
			want: "@types/node",
		},
		{
			name: "namespace without @ prefix",
			artifact: domain.ArtifactIdentity{
				Namespace: "myorg",
				Name:      "package",
			},
			want: "package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPackageName(tt.artifact)
			if got != tt.want {
				t.Errorf("buildPackageName() = %v, want %v", got, tt.want)
			}
		})
	}
}
