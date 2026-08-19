package npm

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type stubScorecardClient struct {
	result *domain.ScorecardResult
	err    error
}

func (s stubScorecardClient) Lookup(context.Context, domain.SourceRepository) (*domain.ScorecardResult, error) {
	return s.result, s.err
}

func TestMetadataEnricher_Enrich(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

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
				},
				"versions": {
					"4.19.1": {
						"license": "(MIT OR Apache-2.0)"
					}
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
		if meta.Licenses == nil {
			t.Fatal("expected Licenses to be set")
		}

		expected := time.Date(2024, 3, 20, 15, 53, 5, 388000000, time.UTC)
		if !meta.PublishedAt.Equal(expected) {
			t.Errorf("PublishedAt = %v, want %v", meta.PublishedAt, expected)
		}
		if len(meta.Licenses) != 2 || meta.Licenses[0] != "MIT" || meta.Licenses[1] != "Apache-2.0" {
			t.Errorf("Licenses = %v, want [MIT Apache-2.0]", meta.Licenses)
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
				},
				"versions": {
					"20.0.0": {
						"licenses": [
							{"type": "MIT"}
						]
					}
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
		if len(meta.Licenses) != 1 || meta.Licenses[0] != "MIT" {
			t.Errorf("Licenses = %v, want [MIT]", meta.Licenses)
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

	t.Run("extracts source repository and scorecard metadata", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"time": {
					"1.0.0": "2024-03-20T15:53:05.388Z"
				},
				"versions": {
					"1.0.0": {
						"repository": {
							"type": "git",
							"url": "git+https://github.com/acme/express.git"
						}
					}
				}
			}`))
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger, stubScorecardClient{
			result: &domain.ScorecardResult{
				Score: ptrNPMScore(8.1),
				Checks: map[string]float64{
					"binary-artifacts": 10,
				},
			},
		})
		enricher.registry = ts.URL

		meta, err := enricher.Enrich(context.Background(), domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "1.0.0",
		})
		require.NoError(t, err)
		require.NotNil(t, meta.SourceRepository)
		assert.Equal(t, "github.com/acme/express", meta.SourceRepository.ProjectURI())
		require.NotNil(t, meta.Scorecard)
		require.NotNil(t, meta.Scorecard.Score)
		assert.InDelta(t, 8.1, *meta.Scorecard.Score, 0.001)
		assert.Equal(t, 10.0, meta.Scorecard.Checks["binary-artifacts"])
	})

	t.Run("marks unsupported source repositories as unavailable scorecard data", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"time": {
					"1.0.0": "2024-03-20T15:53:05.388Z"
				},
				"versions": {
					"1.0.0": {
						"repository": {
							"type": "git",
							"url": "https://gitlab.com/acme/express"
						}
					}
				}
			}`))
		}))
		defer ts.Close()

		enricher := NewMetadataEnricher(http.DefaultClient, logger)
		enricher.registry = ts.URL

		meta, err := enricher.Enrich(context.Background(), domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "express",
			Version:   "1.0.0",
		})
		require.NoError(t, err)
		require.NotNil(t, meta.Scorecard)
		assert.Equal(
			t,
			"npm package does not declare a supported GitHub source repository",
			meta.Scorecard.UnavailableReason,
		)
		assert.Nil(t, meta.SourceRepository)
	})
}

func TestSplitLicenseExpression(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{name: "single SPDX id", value: "MIT", want: []string{"MIT"}},
		{name: "OR expression", value: "(MIT OR Apache-2.0)", want: []string{"MIT", "Apache-2.0"}},
		{
			name:  "WITH exception",
			value: "GPL-2.0-only WITH Classpath-exception-2.0",
			want:  []string{"GPL-2.0-only", "Classpath-exception-2.0"},
		},
		{name: "plus shorthand preserved", value: "GPL-2.0+", want: []string{"GPL-2.0+"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitLicenseExpression(tt.value)
			if len(got) != len(tt.want) {
				t.Fatalf("splitLicenseExpression() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("splitLicenseExpression() = %v, want %v", got, tt.want)
				}
			}
		})
	}
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

func ptrNPMScore(v float64) *float64 {
	return &v
}
