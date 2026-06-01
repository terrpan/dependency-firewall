package upstream

import (
	"fmt"
	"net/http"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type authSecretResolver interface {
	ResolveSecret([]byte) ([]byte, error)
}

func (c *OCIClient) applyRegistryAuth(req *http.Request, auth *domain.UpstreamAuth) error {
	if auth == nil {
		return nil
	}
	secret, err := c.resolveAuthSecret(auth)
	if err != nil {
		return err
	}

	switch auth.Type {
	case domain.UpstreamAuthBearerToken:
		req.Header.Set("Authorization", "Bearer "+string(secret))
	case domain.UpstreamAuthBasic:
		req.SetBasicAuth(auth.Username, string(secret))
	}
	return nil
}

func (c *OCIClient) resolveAuthSecret(auth *domain.UpstreamAuth) ([]byte, error) {
	if auth == nil || auth.Secret == "" {
		return nil, nil
	}
	raw := []byte(auth.Secret)
	if c.secretResolver == nil {
		return raw, nil
	}
	secret, err := c.secretResolver.ResolveSecret(raw)
	if err != nil {
		return nil, fmt.Errorf("resolving upstream auth secret: %w", err)
	}
	return secret, nil
}
