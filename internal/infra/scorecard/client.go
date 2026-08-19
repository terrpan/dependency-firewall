// Package scorecard implements an enrichment client for the hosted Scorecard API.
package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const (
	defaultBaseURL = "https://api.scorecard.dev"
	defaultTimeout = 10 * time.Second
)

// Client queries the hosted Scorecard API for repository score data.
type Client struct {
	httpClient *http.Client
	baseURL    string
	logger     *slog.Logger
}

// NewClient creates a new Scorecard client. If the provided httpClient has no
// timeout configured, a 10-second default is applied.
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

// projectResponse intentionally decodes only the subset of the hosted
// Scorecard schema needed for policy evaluation.
type projectResponse struct {
	Score  *float64             `json:"score"`
	Checks []projectCheckResult `json:"checks"`
}

type projectCheckResult struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// Lookup fetches the hosted Scorecard result for the provided repository.
func (c *Client) Lookup(ctx context.Context, repo domain.SourceRepository) (*domain.ScorecardResult, error) {
	projectURI := repo.ProjectURI()
	if projectURI == "" {
		return nil, fmt.Errorf("%w: source repository is required for Scorecard lookup", domain.ErrEnrichmentFailed)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimRight(c.baseURL, "/")+"/projects/"+projectURI,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", domain.ErrEnrichmentFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrEnrichmentFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &domain.ScorecardResult{
			UnavailableReason: fmt.Sprintf("Scorecard data is unavailable for %s", projectURI),
		}, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: rate limited by Scorecard API", domain.ErrEnrichmentFailed)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: Scorecard API returned status %d", domain.ErrEnrichmentFailed, resp.StatusCode)
	}

	var payload projectResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %v", domain.ErrEnrichmentFailed, err)
	}

	result := &domain.ScorecardResult{}
	if payload.Score != nil {
		result.Score = payload.Score
	}
	if len(payload.Checks) > 0 {
		result.Checks = make(map[string]float64, len(payload.Checks))
		for _, check := range payload.Checks {
			checkName := domain.NormalizeScorecardCheckName(check.Name)
			if checkName == "" {
				continue
			}
			result.Checks[checkName] = check.Score
		}
	}
	if result.Score == nil && len(result.Checks) == 0 {
		result.UnavailableReason = fmt.Sprintf("Scorecard data is unavailable for %s", projectURI)
	}

	c.logger.DebugContext(ctx, "scorecard lookup completed",
		"repository", projectURI,
		"has_score", result.Score != nil,
		"check_count", len(result.Checks),
	)

	return result, nil
}
