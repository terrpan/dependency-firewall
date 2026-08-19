package ocicache

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

func TestDiskCacheRoundTripAndScopeIsolation(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskCache(DiskCacheOptions{RootDir: dir})
	require.NoError(t, err)

	writer, err := cache.StartWrite(
		context.Background(),
		"tenant-a",
		"upstream-a",
		port.OCIArtifactBlob,
		"sha256:abc123",
		port.OCIArtifactDescriptor{
			ContentType: "application/octet-stream",
			Headers: map[string]string{
				"Content-Length": "5",
			},
		},
	)
	require.NoError(t, err)

	_, err = writer.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, writer.Commit(context.Background()))

	resp, err := cache.Get(context.Background(), "tenant-a", "upstream-a", port.OCIArtifactBlob, "sha256:abc123")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/octet-stream", resp.ContentType)
	assert.Equal(t, "5", resp.Headers["Content-Length"])
	assert.Equal(t, "hello", string(body))

	_, err = cache.Get(context.Background(), "tenant-b", "upstream-a", port.OCIArtifactBlob, "sha256:abc123")
	assert.ErrorIs(t, err, domain.ErrCacheMiss)

	_, err = cache.Get(context.Background(), "tenant-a", "upstream-b", port.OCIArtifactBlob, "sha256:abc123")
	assert.ErrorIs(t, err, domain.ErrCacheMiss)
}

func TestDiskCacheAbortLeavesNoEntry(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskCache(DiskCacheOptions{RootDir: dir})
	require.NoError(t, err)

	writer, err := cache.StartWrite(
		context.Background(),
		"tenant-a",
		"upstream-a",
		port.OCIArtifactManifest,
		"sha256:def456",
		port.OCIArtifactDescriptor{
			ContentType: "application/vnd.oci.image.manifest.v1+json",
		},
	)
	require.NoError(t, err)
	_, err = writer.Write([]byte(`{"schemaVersion":2}`))
	require.NoError(t, err)
	require.NoError(t, writer.Abort())

	_, err = cache.Get(context.Background(), "tenant-a", "upstream-a", port.OCIArtifactManifest, "sha256:def456")
	assert.ErrorIs(t, err, domain.ErrCacheMiss)
}

func TestDiskCacheRejectsIncompleteScope(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskCache(DiskCacheOptions{RootDir: dir})
	require.NoError(t, err)

	_, err = cache.Get(context.Background(), "tenant-a", "", port.OCIArtifactBlob, "sha256:abc123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upstream_id")

	_, err = cache.StartWrite(
		context.Background(),
		"",
		"upstream-a",
		port.OCIArtifactBlob,
		"sha256:abc123",
		port.OCIArtifactDescriptor{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

func TestDiskCacheMaxEntriesEvictsOldestPerScope(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskCache(DiskCacheOptions{
		RootDir:    dir,
		MaxEntries: 1,
	})
	require.NoError(t, err)

	writeArtifact := func(upstreamID, digest, body string) {
		writer, err := cache.StartWrite(
			context.Background(),
			"tenant-a",
			upstreamID,
			port.OCIArtifactBlob,
			digest,
			port.OCIArtifactDescriptor{
				ContentType: "application/octet-stream",
			},
		)
		require.NoError(t, err)
		_, err = writer.Write([]byte(body))
		require.NoError(t, err)
		require.NoError(t, writer.Commit(context.Background()))
		time.Sleep(10 * time.Millisecond)
	}

	writeArtifact("upstream-b", "sha256:other", "other")
	writeArtifact("upstream-a", "sha256:first", "one")
	writeArtifact("upstream-a", "sha256:second", "two")

	_, err = cache.Get(context.Background(), "tenant-a", "upstream-a", port.OCIArtifactBlob, "sha256:first")
	assert.ErrorIs(t, err, domain.ErrCacheMiss)

	resp, err := cache.Get(context.Background(), "tenant-a", "upstream-a", port.OCIArtifactBlob, "sha256:second")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "two", string(body))

	otherResp, err := cache.Get(context.Background(), "tenant-a", "upstream-b", port.OCIArtifactBlob, "sha256:other")
	require.NoError(t, err)
	defer otherResp.Body.Close()

	otherBody, err := io.ReadAll(otherResp.Body)
	require.NoError(t, err)
	assert.Equal(t, "other", string(otherBody))
}
