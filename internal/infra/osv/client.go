// Package osv implements an enrichment client for the OSV vulnerability API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const (
	defaultBaseURL = "https://api.osv.dev"
	defaultTimeout = 10 * time.Second
)

// Client queries the OSV API for vulnerability data.
type Client struct {
	httpClient *http.Client
	baseURL    string
	logger     *slog.Logger
}

// NewClient creates a new OSV enrichment client. If the provided httpClient has
// no timeout configured, a 10-second default is applied.
func NewClient(httpClient *http.Client, logger *slog.Logger) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	} else if httpClient.Timeout == 0 {
		httpClient.Timeout = defaultTimeout
	}
	return &Client{
		httpClient: httpClient,
		baseURL:    defaultBaseURL,
		logger:     logger,
	}
}

// queryRequest is the JSON payload sent to the OSV query endpoint.
type queryRequest struct {
	Package queryPackage `json:"package"`
	Version string       `json:"version"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// queryResponse is the JSON response from the OSV query endpoint.
type queryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Enrich fetches vulnerability metadata for the given artifact from the OSV API.
func (c *Client) Enrich(ctx context.Context, artifact domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	if artifact.Ecosystem == domain.EcosystemOCI {
		// OSV does not support OCI/container images directly.
		return &domain.ArtifactMetadata{}, nil
	}

	ecosystem, pkgName := mapArtifactToOSV(artifact)
	if pkgName == "" {
		return &domain.ArtifactMetadata{}, nil
	}

	payload := queryRequest{
		Package: queryPackage{
			Name:      pkgName,
			Ecosystem: ecosystem,
		},
		Version: artifact.Version,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling request: %v", domain.ErrEnrichmentFailed, err)
	}

	url := c.baseURL + "/v1/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", domain.ErrEnrichmentFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrEnrichmentFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: rate limited by OSV API", domain.ErrEnrichmentFailed)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: OSV API returned status %d", domain.ErrEnrichmentFailed, resp.StatusCode)
	}

	var result queryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %v", domain.ErrEnrichmentFailed, err)
	}

	return toArtifactMetadata(result), nil
}

// mapArtifactToOSV maps a domain artifact to the OSV ecosystem name and package name.
func mapArtifactToOSV(a domain.ArtifactIdentity) (ecosystem, pkgName string) {
	switch a.Ecosystem {
	case domain.EcosystemNPM:
		ecosystem = "npm"
		if a.Namespace != "" && strings.HasPrefix(a.Namespace, "@") {
			pkgName = a.Namespace + "/" + a.Name
		} else {
			pkgName = a.Name
		}
	default:
		ecosystem = string(a.Ecosystem)
		pkgName = a.Name
	}
	return ecosystem, pkgName
}

// toArtifactMetadata converts the OSV response to the domain metadata type.
func toArtifactMetadata(resp queryResponse) *domain.ArtifactMetadata {
	meta := &domain.ArtifactMetadata{}
	if len(resp.Vulns) == 0 {
		return meta
	}

	vulns := make([]domain.Vulnerability, 0, len(resp.Vulns))
	var maxCVSS float64
	hasScore := false

	for _, v := range resp.Vulns {
		severity, score := extractSeverity(v.Severity)
		vulns = append(vulns, domain.Vulnerability{
			ID:       v.ID,
			Severity: severity,
			CVSS:     score,
			Summary:  v.Summary,
		})
		if score > 0 {
			hasScore = true
			if score > maxCVSS {
				maxCVSS = score
			}
		}
	}

	meta.Vulnerabilities = vulns
	if hasScore {
		meta.MaxCVSS = &maxCVSS
	}
	return meta
}

// extractSeverity picks the best severity string and CVSS score from the OSV
// severity array using the highest successfully parsed score.
func extractSeverity(severities []osvSeverity) (string, float64) {
	if len(severities) == 0 {
		return "", 0
	}

	bestSeverity := severities[0].Score
	bestScore := parseCVSSScore(severities[0].Score)

	for _, severity := range severities[1:] {
		score := parseCVSSScore(severity.Score)
		if score <= bestScore {
			continue
		}
		bestSeverity = severity.Score
		bestScore = score
	}

	return bestSeverity, bestScore
}

// parseCVSSScore extracts the base score from a CVSS vector string.
// OSV returns CVSS vectors like "CVSS:3.1/AV:N/AC:L/..." — we parse the
// numeric score from severity data. If it is already a plain number, parse that.
func parseCVSSScore(vector string) float64 {
	trimmed := strings.TrimSpace(vector)
	if trimmed == "" {
		return 0
	}

	if score, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return score
	}

	switch {
	case strings.HasPrefix(trimmed, "CVSS:3.0/"):
		cvss30, err := gocvss30.ParseVector(trimmed)
		if err == nil {
			return cvss30.BaseScore()
		}
	case strings.HasPrefix(trimmed, "CVSS:3.1/"):
		cvss31, err := gocvss31.ParseVector(trimmed)
		if err == nil {
			return cvss31.BaseScore()
		}
	case strings.HasPrefix(trimmed, "CVSS:4.0/"):
		cvss40, err := gocvss40.ParseVector(trimmed)
		if err == nil {
			return cvss40.Score()
		}
	}

	return 0
}
