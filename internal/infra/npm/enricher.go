// Package npm provides npm registry metadata enrichment.
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const (
	defaultTimeout  = 10 * time.Second
	defaultRegistry = "https://registry.npmjs.org"
)

// MetadataEnricher fetches npm package metadata to extract publish dates and other registry info.
type MetadataEnricher struct {
	httpClient *http.Client
	registry   string
	logger     *slog.Logger
}

// npmPackageResponse is the relevant subset of the npm registry package JSON response.
type npmPackageResponse struct {
	Time map[string]string `json:"time"` // version -> ISO8601 timestamp
}

// NewMetadataEnricher creates a new npm metadata enricher.
func NewMetadataEnricher(httpClient *http.Client, logger *slog.Logger) *MetadataEnricher {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	} else if httpClient.Timeout == 0 {
		httpClient.Timeout = defaultTimeout
	}
	return &MetadataEnricher{
		httpClient: httpClient,
		registry:   defaultRegistry,
		logger:     logger,
	}
}

// Enrich fetches package metadata from the npm registry to populate PublishedAt.
func (e *MetadataEnricher) Enrich(ctx context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	e.logger.InfoContext(ctx, "npm enricher called",
		"ecosystem", artifact.Ecosystem,
		"name", artifact.Name,
		"version", artifact.Version,
	)

	if artifact.Ecosystem != domain.EcosystemNPM {
		return &domain.ArtifactMetadata{}, nil
	}

	if artifact.Version == "" {
		// Cannot enrich without a specific version.
		return &domain.ArtifactMetadata{}, nil
	}

	pkgName := buildPackageName(artifact)
	url := e.registry + "/" + pkgName

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", domain.ErrEnrichmentFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		e.logger.WarnContext(ctx, "npm registry request failed",
			"package", pkgName,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", domain.ErrEnrichmentFailed, err)
	}
	defer resp.Body.Close()

	e.logger.InfoContext(ctx, "npm registry response received",
		"package", pkgName,
		"status", resp.StatusCode,
	)

	if resp.StatusCode == http.StatusNotFound {
		// Package doesn't exist - not an error for enrichment purposes.
		return &domain.ArtifactMetadata{}, nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: rate limited by npm registry", domain.ErrEnrichmentFailed)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: npm registry returned status %d", domain.ErrEnrichmentFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %v", domain.ErrEnrichmentFailed, err)
	}

	var pkgData npmPackageResponse
	if err := json.Unmarshal(body, &pkgData); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %v", domain.ErrEnrichmentFailed, err)
	}

	meta := &domain.ArtifactMetadata{}

	// Extract the publish timestamp for the specific version.
	if timeStr, ok := pkgData.Time[artifact.Version]; ok {
		publishedAt, parseErr := time.Parse(time.RFC3339, timeStr)
		if parseErr != nil {
			e.logger.WarnContext(ctx, "failed to parse publish time",
				"package", pkgName,
				"version", artifact.Version,
				"time", timeStr,
				"error", parseErr,
			)
		} else {
			meta.PublishedAt = &publishedAt
			e.logger.InfoContext(ctx, "extracted publish time",
				"package", pkgName,
				"version", artifact.Version,
				"published_at", publishedAt,
			)
		}
	} else {
		e.logger.WarnContext(ctx, "version not found in time map",
			"package", pkgName,
			"version", artifact.Version,
			"available_versions", len(pkgData.Time),
		)
	}

	return meta, nil
}

// buildPackageName constructs the full npm package name from the artifact identity.
func buildPackageName(artifact domain.ArtifactIdentity) string {
	if artifact.Namespace != "" && strings.HasPrefix(artifact.Namespace, "@") {
		return artifact.Namespace + "/" + artifact.Name
	}
	return artifact.Name
}
