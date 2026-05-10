package upstream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestOCIClientFetchMetadata_FollowsBearerChallenge(t *testing.T) {
	const token = "test-token"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			assert.Equal(t, "registry.example", r.URL.Query().Get("service"))
			assert.Equal(t, "repository:library/nginx:pull", r.URL.Query().Get("scope"))
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"token": token}))
		case "/v2/library/nginx/manifests/1.25.3":
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.example",scope="repository:library/nginx:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			assert.Equal(t, ociAcceptHeaders, r.Header.Get("Accept"))
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write([]byte(`{"schemaVersion":2}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewOCIClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL}
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: "library",
		Name:      "nginx",
		Version:   "1.25.3",
	}

	resp, err := client.FetchMetadata(context.Background(), upstream, artifact)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `{"schemaVersion":2}`, string(body))
}

func TestOCIClientFetchContent_FollowsBearerChallenge(t *testing.T) {
	const token = "blob-token"
	const digest = "sha256:abc123"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			assert.Equal(t, "repository:library/nginx:pull", r.URL.Query().Get("scope"))
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"access_token": token}))
		case "/v2/library/nginx/blobs/" + digest:
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",scope="repository:library/nginx:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("blob-bytes"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewOCIClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL + "/v2/library/nginx"}

	resp, err := client.FetchContent(context.Background(), upstream, digest)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "blob-bytes", string(body))
}

func TestOCIClientResolveReference_FollowsBearerChallenge(t *testing.T) {
	const token = "head-token"
	const digest = "sha256:deadbeef"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"token": token}))
		case "/v2/library/nginx/manifests/1.25.3":
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",scope="repository:library/nginx:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			assert.Equal(t, http.MethodHead, r.Method)
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewOCIClient(srv.Client())
	upstream := domain.Upstream{BaseURL: srv.URL}
	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: "library",
		Name:      "nginx",
		Version:   "1.25.3",
	}

	resolvedDigest, err := client.ResolveReference(context.Background(), upstream, artifact)
	require.NoError(t, err)
	assert.Equal(t, digest, resolvedDigest)
}

func TestOCIClientFetchMetadata_UsesBasicAuthForBearerTokenChallenge(t *testing.T) {
	const token = "private-token"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			username, password, ok := r.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, "robot", username)
			assert.Equal(t, "registry-pat", password)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"token": token}))
		case "/v2/acme/app/manifests/1.0.0":
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",scope="repository:acme/app:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"schemaVersion":2}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewOCIClient(srv.Client())
	upstream := domain.Upstream{
		BaseURL: srv.URL,
		Auth: &domain.UpstreamAuth{
			Type:     domain.UpstreamAuthBasic,
			Username: "robot",
			Secret:   "registry-pat",
		},
	}
	artifact := domain.ArtifactIdentity{Ecosystem: domain.EcosystemOCI, Namespace: "acme", Name: "app", Version: "1.0.0"}

	resp, err := client.FetchMetadata(context.Background(), upstream, artifact)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestOCIClientFetchMetadata_UsesStaticBearerToken(t *testing.T) {
	const token = "static-token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	}))
	defer srv.Close()

	client := NewOCIClient(srv.Client())
	upstream := domain.Upstream{
		BaseURL: srv.URL,
		Auth: &domain.UpstreamAuth{
			Type:   domain.UpstreamAuthBearerToken,
			Secret: token,
		},
	}
	artifact := domain.ArtifactIdentity{Ecosystem: domain.EcosystemOCI, Namespace: "acme", Name: "app", Version: "1.0.0"}

	resp, err := client.FetchMetadata(context.Background(), upstream, artifact)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
