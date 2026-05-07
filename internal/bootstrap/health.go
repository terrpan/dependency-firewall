// health.go adapts database, cache, and remote proxy checks to health service interfaces.
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/danielterry/dependency-firewall/internal/core/service"
)

type dbHealthChecker struct{ pool *pgxpool.Pool }

func (c *dbHealthChecker) Ping(ctx context.Context) error { return c.pool.Ping(ctx) }

type cacheHealthChecker struct{ client valkeygo.Client }

func (c *cacheHealthChecker) Ping(ctx context.Context) error {
	return c.client.Do(ctx, c.client.B().Ping().Build()).Error()
}

type proxyHealthChecker struct {
	url    string
	client *http.Client
}

type proxyHealthResponse struct {
	Status string `json:"status"`
	Proxy  *struct {
		Status    string    `json:"status"`
		Message   string    `json:"message"`
		Timestamp time.Time `json:"timestamp"`
	} `json:"proxy"`
	Bundle *struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"bundle"`
}

func (c *proxyHealthChecker) CheckStatus(ctx context.Context) service.ComponentStatus {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return service.ComponentStatus{
			Status:  "unreachable",
			Message: fmt.Sprintf("building proxy health request: %v", err),
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return service.ComponentStatus{
			Status:  "unreachable",
			Message: fmt.Sprintf("proxy health check failed: %v", err),
		}
	}
	defer resp.Body.Close()

	var payload proxyHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return service.ComponentStatus{
			Status:  "unreachable",
			Message: fmt.Sprintf("decoding proxy health response: %v", err),
		}
	}

	if payload.Proxy != nil {
		message := strings.TrimSpace(payload.Proxy.Message)
		if payload.Bundle != nil && strings.TrimSpace(payload.Bundle.Status) != "" {
			if message == "" {
				message = fmt.Sprintf("bundle=%s", payload.Bundle.Status)
			} else {
				message = fmt.Sprintf("%s; bundle=%s", message, payload.Bundle.Status)
			}
		}

		return service.ComponentStatus{
			Status:    payload.Proxy.Status,
			Message:   message,
			Timestamp: payload.Proxy.Timestamp,
		}
	}

	status := strings.TrimSpace(payload.Status)
	if status == "" {
		status = resp.Status
	}
	message := "proxy health endpoint reachable"
	if payload.Bundle != nil && strings.TrimSpace(payload.Bundle.Status) != "" {
		message = fmt.Sprintf("%s; bundle=%s", message, payload.Bundle.Status)
	}

	return service.ComponentStatus{
		Status:  status,
		Message: message,
	}
}
