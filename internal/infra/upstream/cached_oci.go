package upstream

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// CachedOCIClient decorates an upstream client with tenant-aware OCI artifact caching.
type CachedOCIClient struct {
	delegate port.UpstreamClient
	cache    port.OCIArtifactCache
	logger   *slog.Logger
}

type cacheReadCloser struct {
	ctx      context.Context
	source   io.ReadCloser
	writer   port.OCIArtifactWriter
	logger   *slog.Logger
	tenantID string
	kind     port.OCIArtifactKind
	digest   string
}

// NewCachedOCIClient creates a cache-backed OCI client.
func NewCachedOCIClient(delegate port.UpstreamClient, cache port.OCIArtifactCache, logger *slog.Logger) *CachedOCIClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &CachedOCIClient{
		delegate: delegate,
		cache:    cache,
		logger:   logger,
	}
}

// FetchMetadata fetches OCI manifests, consulting the cache when a digest is available.
func (c *CachedOCIClient) FetchMetadata(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (*port.UpstreamResponse, error) {
	if artifact.Digest != "" {
		cached, err := c.cache.Get(ctx, upstream.TenantID, port.OCIArtifactManifest, artifact.Digest)
		if err == nil {
			c.logger.Debug("OCI manifest cache hit",
				"tenant_id", upstream.TenantID,
				"digest", artifact.Digest,
			)
			return cached, nil
		}
		if !errors.Is(err, domain.ErrCacheMiss) {
			c.logger.Warn("OCI manifest cache get failed",
				"error", err,
				"tenant_id", upstream.TenantID,
				"digest", artifact.Digest,
			)
		}
	}

	resp, err := c.delegate.FetchMetadata(ctx, upstream, artifact)
	if err != nil {
		return nil, err
	}
	return c.wrapResponse(ctx, upstream.TenantID, port.OCIArtifactManifest, artifact.Digest, resp)
}

// FetchContent fetches OCI blobs, consulting the cache first by tenant and digest.
func (c *CachedOCIClient) FetchContent(ctx context.Context, upstream domain.Upstream, digest string) (*port.UpstreamResponse, error) {
	cached, err := c.cache.Get(ctx, upstream.TenantID, port.OCIArtifactBlob, digest)
	if err == nil {
		c.logger.Debug("OCI blob cache hit",
			"tenant_id", upstream.TenantID,
			"digest", digest,
		)
		return cached, nil
	}
	if !errors.Is(err, domain.ErrCacheMiss) {
		c.logger.Warn("OCI blob cache get failed",
			"error", err,
			"tenant_id", upstream.TenantID,
			"digest", digest,
		)
	}

	resp, err := c.delegate.FetchContent(ctx, upstream, digest)
	if err != nil {
		return nil, err
	}
	return c.wrapResponse(ctx, upstream.TenantID, port.OCIArtifactBlob, digest, resp)
}

// ResolveReference delegates tag resolution to the wrapped upstream client.
func (c *CachedOCIClient) ResolveReference(ctx context.Context, upstream domain.Upstream, artifact domain.ArtifactIdentity) (string, error) {
	return c.delegate.ResolveReference(ctx, upstream, artifact)
}

func (c *CachedOCIClient) wrapResponse(ctx context.Context, tenantID string, kind port.OCIArtifactKind, digest string, resp *port.UpstreamResponse) (*port.UpstreamResponse, error) {
	if digest == "" || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == nil {
		return resp, nil
	}

	writer, err := c.cache.StartWrite(ctx, tenantID, kind, digest, port.OCIArtifactDescriptor{
		ContentType: resp.ContentType,
		Headers:     cloneStringMap(resp.Headers),
	})
	if err != nil {
		c.logger.Warn("OCI cache start write failed",
			"error", err,
			"tenant_id", tenantID,
			"kind", kind,
			"digest", digest,
		)
		return resp, nil
	}

	resp.Body = &cacheReadCloser{
		ctx:      ctx,
		source:   resp.Body,
		writer:   writer,
		logger:   c.logger,
		tenantID: tenantID,
		kind:     kind,
		digest:   digest,
	}
	return resp, nil
}

func (r *cacheReadCloser) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if n > 0 && r.writer != nil {
		if _, writeErr := r.writer.Write(p[:n]); writeErr != nil {
			r.logger.Warn("OCI cache write failed; continuing without cache fill",
				"error", writeErr,
				"tenant_id", r.tenantID,
				"kind", r.kind,
				"digest", r.digest,
			)
			_ = r.writer.Abort()
			r.writer = nil
		}
	}

	if err == io.EOF && r.writer != nil {
		if commitErr := r.writer.Commit(r.ctx); commitErr != nil {
			r.logger.Warn("OCI cache commit failed",
				"error", commitErr,
				"tenant_id", r.tenantID,
				"kind", r.kind,
				"digest", r.digest,
			)
		}
		r.writer = nil
	}
	if err != nil && err != io.EOF && r.writer != nil {
		_ = r.writer.Abort()
		r.writer = nil
	}

	return n, err
}

func (r *cacheReadCloser) Close() error {
	if r.writer != nil {
		_ = r.writer.Abort()
		r.writer = nil
	}
	return r.source.Close()
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
