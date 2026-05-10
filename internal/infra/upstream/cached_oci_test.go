package upstream

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

type stubOCIArtifactCache struct {
	getResp           *port.UpstreamResponse
	getErr            error
	getCalls          int
	lastGetTenantID   string
	lastGetUpstreamID string
	lastGetKind       port.OCIArtifactKind
	lastGetDigest     string

	startWriteCalls   int
	lastWriteTenant   string
	lastWriteUpstream string
	lastWriteKind     port.OCIArtifactKind
	lastWriteDigest   string
	lastDescriptor    port.OCIArtifactDescriptor
	writer            *stubOCIArtifactWriter
	startWriteErr     error
}

func (s *stubOCIArtifactCache) Get(_ context.Context, tenantID, upstreamID string, kind port.OCIArtifactKind, digest string) (*port.UpstreamResponse, error) {
	s.getCalls++
	s.lastGetTenantID = tenantID
	s.lastGetUpstreamID = upstreamID
	s.lastGetKind = kind
	s.lastGetDigest = digest
	return s.getResp, s.getErr
}

func (s *stubOCIArtifactCache) StartWrite(_ context.Context, tenantID, upstreamID string, kind port.OCIArtifactKind, digest string, descriptor port.OCIArtifactDescriptor) (port.OCIArtifactWriter, error) {
	s.startWriteCalls++
	s.lastWriteTenant = tenantID
	s.lastWriteUpstream = upstreamID
	s.lastWriteKind = kind
	s.lastWriteDigest = digest
	s.lastDescriptor = descriptor
	if s.writer == nil {
		s.writer = &stubOCIArtifactWriter{}
	}
	return s.writer, s.startWriteErr
}

type stubOCIArtifactWriter struct {
	buf         bytes.Buffer
	commitCalls int
	abortCalls  int
}

func (s *stubOCIArtifactWriter) Write(p []byte) (int, error) {
	return s.buf.Write(p)
}

func (s *stubOCIArtifactWriter) Commit(context.Context) error {
	s.commitCalls++
	return nil
}

func (s *stubOCIArtifactWriter) Abort() error {
	s.abortCalls++
	return nil
}

type stubUpstreamClient struct {
	metadataResp  *port.UpstreamResponse
	metadataErr   error
	metadataCalls int
	contentResp   *port.UpstreamResponse
	contentErr    error
	contentCalls  int
	resolveDigest string
	resolveErr    error
}

func (s *stubUpstreamClient) FetchMetadata(context.Context, domain.Upstream, domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	s.metadataCalls++
	return s.metadataResp, s.metadataErr
}

func (s *stubUpstreamClient) FetchContent(context.Context, domain.Upstream, string) (*port.UpstreamResponse, error) {
	s.contentCalls++
	return s.contentResp, s.contentErr
}

func (s *stubUpstreamClient) ResolveReference(context.Context, domain.Upstream, domain.ArtifactIdentity) (string, error) {
	return s.resolveDigest, s.resolveErr
}

func TestCachedOCIClientFetchContent_CacheHitBypassesDelegate(t *testing.T) {
	cache := &stubOCIArtifactCache{
		getResp: &port.UpstreamResponse{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte("cached"))),
		},
	}
	delegate := &stubUpstreamClient{}
	client := NewCachedOCIClient(delegate, cache, nil)

	resp, err := client.FetchContent(context.Background(), domain.Upstream{ID: "upstream-1", TenantID: "tenant-1"}, "sha256:abc")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, 1, cache.getCalls)
	assert.Equal(t, "tenant-1", cache.lastGetTenantID)
	assert.Equal(t, "upstream-1", cache.lastGetUpstreamID)
	assert.Equal(t, 0, delegate.contentCalls)
	assert.Equal(t, "cached", string(body))
}

func TestCachedOCIClientFetchContent_CacheMissStreamsAndCommits(t *testing.T) {
	cache := &stubOCIArtifactCache{getErr: domain.ErrCacheMiss, writer: &stubOCIArtifactWriter{}}
	delegate := &stubUpstreamClient{
		contentResp: &port.UpstreamResponse{
			StatusCode:  200,
			ContentType: "application/octet-stream",
			Headers:     map[string]string{"Content-Length": "4"},
			Body:        io.NopCloser(bytes.NewReader([]byte("blob"))),
		},
	}
	client := NewCachedOCIClient(delegate, cache, nil)

	resp, err := client.FetchContent(context.Background(), domain.Upstream{ID: "upstream-1", TenantID: "tenant-1"}, "sha256:abc")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, "blob", string(body))
	assert.Equal(t, 1, delegate.contentCalls)
	assert.Equal(t, 1, cache.startWriteCalls)
	assert.Equal(t, 1, cache.writer.commitCalls)
	assert.Equal(t, 0, cache.writer.abortCalls)
	assert.Equal(t, "blob", cache.writer.buf.String())
	assert.Equal(t, "tenant-1", cache.lastWriteTenant)
	assert.Equal(t, "upstream-1", cache.lastWriteUpstream)
	assert.Equal(t, port.OCIArtifactBlob, cache.lastWriteKind)
}

func TestCachedOCIClientFetchContent_MissingUpstreamIDBypassesCache(t *testing.T) {
	cache := &stubOCIArtifactCache{
		getResp: &port.UpstreamResponse{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte("cached"))),
		},
	}
	delegate := &stubUpstreamClient{
		contentResp: &port.UpstreamResponse{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte("delegate"))),
		},
	}
	client := NewCachedOCIClient(delegate, cache, nil)

	resp, err := client.FetchContent(context.Background(), domain.Upstream{TenantID: "tenant-1"}, "sha256:abc")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, 0, cache.getCalls)
	assert.Equal(t, 0, cache.startWriteCalls)
	assert.Equal(t, 1, delegate.contentCalls)
	assert.Equal(t, "delegate", string(body))
}

func TestCachedOCIClientFetchMetadata_OnlyCachesWhenDigestPresent(t *testing.T) {
	cache := &stubOCIArtifactCache{getErr: domain.ErrCacheMiss, writer: &stubOCIArtifactWriter{}}
	delegate := &stubUpstreamClient{
		metadataResp: &port.UpstreamResponse{
			StatusCode:  200,
			ContentType: "application/vnd.oci.image.manifest.v1+json",
			Body:        io.NopCloser(bytes.NewReader([]byte(`{"schemaVersion":2}`))),
		},
	}
	client := NewCachedOCIClient(delegate, cache, nil)
	upstream := domain.Upstream{ID: "upstream-1", TenantID: "tenant-1"}

	resp, err := client.FetchMetadata(context.Background(), upstream, domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: "library",
		Name:      "nginx",
		Version:   "latest",
	})
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, 0, cache.getCalls)
	assert.Equal(t, 0, cache.startWriteCalls)

	resp, err = client.FetchMetadata(context.Background(), upstream, domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemOCI,
		Namespace: "library",
		Name:      "nginx",
		Digest:    "sha256:abc",
		Version:   "latest",
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, 1, cache.getCalls)
	assert.Equal(t, "tenant-1", cache.lastGetTenantID)
	assert.Equal(t, "upstream-1", cache.lastGetUpstreamID)
	assert.Equal(t, 1, cache.startWriteCalls)
	assert.Equal(t, "tenant-1", cache.lastWriteTenant)
	assert.Equal(t, "upstream-1", cache.lastWriteUpstream)
	assert.Equal(t, port.OCIArtifactManifest, cache.lastWriteKind)
	assert.Equal(t, "sha256:abc", cache.lastWriteDigest)
}
