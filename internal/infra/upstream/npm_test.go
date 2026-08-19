package upstream

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestNPMClient_ListManifestDependencyNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/morgan/1.10.0", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name":"morgan","version":"1.10.0",
			"dependencies":{"debug":"2.6.9","on-finished":"~2.3.0"},
			"optionalDependencies":{"fsevents":"^2.0.0"},
			"peerDependencies":{"react":">=16"}
		}`))
	}))
	defer srv.Close()

	client := NewNPMClient(srv.Client())
	names, err := client.ListManifestDependencyNames(
		context.Background(),
		domain.Upstream{BaseURL: srv.URL},
		domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "morgan",
			Version:   "1.10.0",
		},
	)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"debug", "on-finished", "fsevents", "react"}, names)
}

func TestNPMClient_ListManifestDependencyNames_RequiresVersion(t *testing.T) {
	client := NewNPMClient(&http.Client{})
	_, err := client.ListManifestDependencyNames(
		context.Background(),
		domain.Upstream{BaseURL: "http://localhost"},
		domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "morgan",
		},
	)
	require.Error(t, err)
}

func TestNPMClient_GetManifest_ScopedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// url.PathEscape keeps @ as-is (valid path char) but encodes / as %2F.
		assert.Equal(t, "/@scope%2Fmypackage/1.0.0", r.URL.RawPath)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"@scope/mypackage","version":"1.0.0"}`))
	}))
	defer srv.Close()

	client := NewNPMClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL}
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Namespace: "@scope",
		Name:      "mypackage",
		Version:   "1.0.0",
	}

	resp, err := client.FetchMetadata(context.Background(), upstream, artifact)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.ContentType)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "@scope/mypackage")
}

func TestNPMClient_GetManifest_UnscopedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/express", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"express"}`))
	}))
	defer srv.Close()

	client := NewNPMClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL}
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "express",
	}

	resp, err := client.FetchMetadata(context.Background(), upstream, artifact)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "express")
}

func TestNPMClient_GetBlob_TarballURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/express/-/express-4.18.2.tgz", r.URL.Path)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("fake-tarball-bytes"))
	}))
	defer srv.Close()

	client := NewNPMClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL}

	// The digest for npm encodes the tarball path segment.
	tarballPath := "express/-/express-4.18.2.tgz"
	resp, err := client.FetchContent(context.Background(), upstream, tarballPath)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "fake-tarball-bytes", string(body))
}

func TestNPMClient_ResolveTag_DistTagsLatest(t *testing.T) {
	metadata := map[string]any{
		"name": "express",
		"dist-tags": map[string]string{
			"latest": "4.18.2",
			"next":   "5.0.0-beta.1",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/express", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	}))
	defer srv.Close()

	client := NewNPMClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL}
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "express",
		Version:   "latest",
	}

	version, err := client.ResolveReference(context.Background(), upstream, artifact)
	require.NoError(t, err)
	assert.Equal(t, "4.18.2", version)
}

func TestNPMClient_404_ReturnsErrArtifactNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := NewNPMClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL}
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "nonexistent",
	}

	t.Run("GetManifest", func(t *testing.T) {
		_, err := client.FetchMetadata(context.Background(), upstream, artifact)
		assert.ErrorIs(t, err, domain.ErrArtifactNotFound)
	})

	t.Run("GetBlob", func(t *testing.T) {
		_, err := client.FetchContent(context.Background(), upstream, "nonexistent/-/nonexistent-1.0.0.tgz")
		assert.ErrorIs(t, err, domain.ErrArtifactNotFound)
	})

	t.Run("ResolveTag", func(t *testing.T) {
		_, err := client.ResolveReference(context.Background(), upstream, artifact)
		assert.ErrorIs(t, err, domain.ErrArtifactNotFound)
	})
}

func TestNPMClient_ConnectionError_ReturnsErrUpstreamUnavailable(t *testing.T) {
	// Start a listener to get a valid port, then close it immediately.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	client := NewNPMClient(&http.Client{})
	upstream := domain.Upstream{BaseURL: "http://" + addr}
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "express",
		Version:   "latest",
	}

	t.Run("GetManifest", func(t *testing.T) {
		_, err := client.FetchMetadata(context.Background(), upstream, artifact)
		assert.ErrorIs(t, err, domain.ErrUpstreamUnavailable)
	})

	t.Run("GetBlob", func(t *testing.T) {
		_, err := client.FetchContent(context.Background(), upstream, "express/-/express-4.18.2.tgz")
		assert.ErrorIs(t, err, domain.ErrUpstreamUnavailable)
	})

	t.Run("ResolveTag", func(t *testing.T) {
		_, err := client.ResolveReference(context.Background(), upstream, artifact)
		assert.ErrorIs(t, err, domain.ErrUpstreamUnavailable)
	})
}
