// Package npm provides npm registry metadata enrichment.
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
	scorecards scorecardClient
}

// npmPackageResponse is the relevant subset of the npm registry package JSON response.
type npmPackageResponse struct {
	Time       map[string]string            `json:"time"`       // version -> ISO8601 timestamp
	Versions   map[string]npmPackageVersion `json:"versions"`   // version -> package.json fields
	Repository any                          `json:"repository"` // top-level package repository metadata
}

type npmPackageVersion struct {
	License    any                `json:"license"`
	Licenses   []npmLicenseObject `json:"licenses"`
	Repository any                `json:"repository"`
}

type npmLicenseObject struct {
	Type string `json:"type"`
}

type scorecardClient interface {
	Lookup(ctx context.Context, repo domain.SourceRepository) (*domain.ScorecardResult, error)
}

// NewMetadataEnricher creates a new npm metadata enricher.
func NewMetadataEnricher(httpClient *http.Client, logger *slog.Logger, scorecards ...scorecardClient) *MetadataEnricher {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	} else if httpClient.Timeout == 0 {
		httpClient.Timeout = defaultTimeout
	}
	var scorecardLookup scorecardClient
	if len(scorecards) > 0 {
		scorecardLookup = scorecards[0]
	}
	return &MetadataEnricher{
		httpClient: httpClient,
		registry:   defaultRegistry,
		logger:     logger,
		scorecards: scorecardLookup,
	}
}

// Enrich fetches package metadata from the npm registry to populate PublishedAt and Licenses.
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

	if versionData, ok := pkgData.Versions[artifact.Version]; ok {
		meta.Licenses = extractVersionLicenses(versionData)
		sourceRepo, scorecardUnavailableReason := resolveSourceRepository(pkgData, versionData)
		if sourceRepo != nil {
			meta.SourceRepository = sourceRepo
			if e.scorecards != nil {
				scorecardResult, lookupErr := e.scorecards.Lookup(ctx, *sourceRepo)
				if lookupErr != nil {
					e.logger.WarnContext(ctx, "scorecard lookup failed",
						"repository", sourceRepo.ProjectURI(),
						"error", lookupErr,
					)
					meta.Scorecard = &domain.ScorecardResult{
						UnavailableReason: fmt.Sprintf("Scorecard data is unavailable for %s", sourceRepo.ProjectURI()),
					}
				} else {
					meta.Scorecard = scorecardResult
				}
			}
		} else if scorecardUnavailableReason != "" {
			meta.Scorecard = &domain.ScorecardResult{UnavailableReason: scorecardUnavailableReason}
		}
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

func extractVersionLicenses(version npmPackageVersion) []string {
	var licenses []string
	seen := make(map[string]struct{})

	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		licenses = append(licenses, value)
	}

	switch license := version.License.(type) {
	case string:
		for _, item := range splitLicenseExpression(license) {
			add(item)
		}
	case map[string]any:
		if licenseType, ok := license["type"].(string); ok {
			for _, item := range splitLicenseExpression(licenseType) {
				add(item)
			}
		}
	}

	for _, item := range version.Licenses {
		for _, token := range splitLicenseExpression(item.Type) {
			add(token)
		}
	}

	return licenses
}

func splitLicenseExpression(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case '(', ')':
			return true
		}
		return false
	})

	var result []string
	for _, field := range fields {
		for _, token := range strings.Fields(field) {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			switch strings.ToUpper(token) {
			case "AND", "OR", "WITH":
				continue
			}
			result = append(result, token)
		}
	}

	if len(result) == 0 {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return []string{trimmed}
		}
	}

	return result
}

func resolveSourceRepository(pkg npmPackageResponse, version npmPackageVersion) (*domain.SourceRepository, string) {
	candidates := []any{version.Repository, pkg.Repository}
	var sawRepositoryValue bool

	for _, candidate := range candidates {
		rawValue, ok := repositoryValue(candidate)
		if !ok {
			continue
		}
		sawRepositoryValue = true
		repo, err := normalizeGitHubRepository(rawValue)
		if err == nil {
			return repo, ""
		}
	}

	if sawRepositoryValue {
		return nil, "npm package does not declare a supported GitHub source repository"
	}

	return nil, "npm package does not declare a source repository"
}

func repositoryValue(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		return trimmed, trimmed != ""
	case map[string]any:
		if rawURL, ok := typed["url"].(string); ok {
			trimmed := strings.TrimSpace(rawURL)
			return trimmed, trimmed != ""
		}
	}

	return "", false
}

func normalizeGitHubRepository(raw string) (*domain.SourceRepository, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("repository is empty")
	}

	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "github:"):
		return parseGitHubRepositoryPath(trimmed[len("github:"):])
	case strings.HasPrefix(lower, "git@github.com:"):
		return parseGitHubRepositoryPath(trimmed[len("git@github.com:"):])
	}

	normalized := strings.TrimPrefix(trimmed, "git+")
	if strings.HasPrefix(strings.ToLower(normalized), "git://") {
		normalized = "https://" + normalized[len("git://"):]
	}
	if strings.HasPrefix(strings.ToLower(normalized), "ssh://git@github.com/") {
		return parseGitHubRepositoryPath(normalized[len("ssh://git@github.com/"):])
	}
	if looksLikeGitHubShorthand(normalized) {
		return parseGitHubRepositoryPath(normalized)
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(parsed.Hostname()) != "github.com" {
		return nil, fmt.Errorf("unsupported repository host %q", parsed.Hostname())
	}

	return parseGitHubRepositoryPath(parsed.Path)
}

func parseGitHubRepositoryPath(path string) (*domain.SourceRepository, error) {
	trimmed := strings.Trim(strings.TrimSpace(path), "/")
	trimmed = strings.TrimSuffix(trimmed, ".git")
	if index := strings.IndexAny(trimmed, "#?"); index >= 0 {
		trimmed = trimmed[:index]
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("repository path %q must include owner and repo", path)
	}

	owner := strings.TrimSpace(parts[0])
	repo := strings.TrimSpace(parts[1])
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("repository path %q must include owner and repo", path)
	}

	return &domain.SourceRepository{
		Host:  "github.com",
		Owner: owner,
		Repo:  repo,
	}, nil
}

func looksLikeGitHubShorthand(value string) bool {
	if strings.Contains(value, "://") || strings.Contains(value, "@") {
		return false
	}
	parts := strings.Split(strings.Trim(value, "/"), "/")
	return len(parts) == 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != ""
}
