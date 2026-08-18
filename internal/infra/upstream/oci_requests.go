package upstream

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

func ociManifestURL(upstream domain.Upstream, artifact domain.ArtifactIdentity, ref string) string {
	return fmt.Sprintf("%s/v2/%s/manifests/%s",
		strings.TrimRight(upstream.BaseURL, "/"),
		repoPath(artifact),
		ref,
	)
}

func (c *OCIClient) executeOCIGet(
	ctx context.Context,
	upstream domain.Upstream,
	url string,
) (*port.UpstreamResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GET request: %w", err)
	}

	if strings.Contains(req.URL.Path, "/manifests/") {
		req.Header.Set("Accept", ociAcceptHeaders)
	}

	resp, err := c.doOCIRequest(req, upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUpstreamUnavailable, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, domain.ErrArtifactNotFound
	}

	return newUpstreamResponse(resp), nil
}

func (c *OCIClient) resolveTagHead(ctx context.Context, upstream domain.Upstream, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating HEAD request: %w", err)
	}
	req.Header.Set("Accept", ociAcceptHeaders)

	resp, err := c.doOCIRequest(req, upstream)
	if err != nil {
		return "", fmt.Errorf("%w: %w", domain.ErrUpstreamUnavailable, err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", domain.ErrArtifactNotFound
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header in HEAD response")
	}
	return digest, nil
}

func (c *OCIClient) resolveTagGet(ctx context.Context, upstream domain.Upstream, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating GET request: %w", err)
	}
	req.Header.Set("Accept", ociAcceptHeaders)

	resp, err := c.doOCIRequest(req, upstream)
	if err != nil {
		return "", fmt.Errorf("%w: %w", domain.ErrUpstreamUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return "", domain.ErrArtifactNotFound
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header in GET response")
	}
	return digest, nil
}
