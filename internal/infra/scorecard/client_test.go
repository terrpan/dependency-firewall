package scorecard

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestClientLookup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("parses aggregate and per-check scores", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/projects/github.com/acme/example", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"score": 8.4,
				"checks": [
					{"name": "Binary-Artifacts", "score": 10},
					{"name": "Branch Protection", "score": 7}
				]
			}`))
		}))
		defer server.Close()

		client := NewClient(server.Client(), logger)
		client.baseURL = server.URL

		result, err := client.Lookup(context.Background(), domain.SourceRepository{
			Host:  "github.com",
			Owner: "acme",
			Repo:  "example",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.Score)
		assert.InDelta(t, 8.4, *result.Score, 0.001)
		assert.Equal(t, map[string]float64{
			"binary-artifacts":  10,
			"branch-protection": 7,
		}, result.Checks)
		assert.Empty(t, result.UnavailableReason)
	})

	t.Run("parses schema-shaped payloads and preserves negative check scores", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/projects/github.com/expressjs/express", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"date": "2026-05-04T21:39:40Z",
				"repo": {
					"name": "github.com/expressjs/express",
					"commit": "f873ac23124ffcff8c040b4bd257b32c29828d53"
				},
				"scorecard": {
					"version": "v5.3.0",
					"commit": "c22063e786c11f9dd714d777a687ff7c4599b600"
				},
				"score": 8.9,
				"checks": [
					{
						"name": "Code-Review",
						"score": 10,
						"reason": "all changesets reviewed",
						"details": null,
						"documentation": {
							"short": "Determines if the project requires human code review before pull requests are merged.",
							"url": "https://github.com/ossf/scorecard/docs/checks.md#code-review"
						}
					},
					{
						"name": "Branch-Protection",
						"score": -1,
						"reason": "internal error",
						"details": null,
						"documentation": {
							"short": "Determines if branches are protected.",
							"url": "https://github.com/ossf/scorecard/docs/checks.md#branch-protection"
						}
					}
				]
			}`))
		}))
		defer server.Close()

		client := NewClient(server.Client(), logger)
		client.baseURL = server.URL

		result, err := client.Lookup(context.Background(), domain.SourceRepository{
			Host:  "github.com",
			Owner: "expressjs",
			Repo:  "express",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.Score)
		assert.InDelta(t, 8.9, *result.Score, 0.001)
		assert.Equal(t, map[string]float64{
			"code-review":       10,
			"branch-protection": -1,
		}, result.Checks)
		assert.Empty(t, result.UnavailableReason)
	})

	t.Run("maps not found to unavailable scorecard data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.NotFound(w, nil)
		}))
		defer server.Close()

		client := NewClient(server.Client(), logger)
		client.baseURL = server.URL

		result, err := client.Lookup(context.Background(), domain.SourceRepository{
			Host:  "github.com",
			Owner: "acme",
			Repo:  "missing",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Scorecard data is unavailable for github.com/acme/missing", result.UnavailableReason)
	})
}
