package condition

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Allowlist matches when the artifact's namespace is in the configured list.
// A match on an allowlist indicates the artifact should be allowed.
type Allowlist struct{}

// Evaluate checks whether the artifact's namespace is in the allowed namespaces.
func (a Allowlist) Evaluate(req domain.AccessRequest, config map[string]any) (bool, string, error) {
	namespaces, err := extractNamespaces(config)
	if err != nil {
		return false, "", err
	}

	ns := req.Artifact.Namespace
	for _, allowed := range namespaces {
		if ns == allowed {
			return true, fmt.Sprintf("namespace %q is allowed", ns), nil
		}
	}

	return false, "", nil
}

// Blocklist matches when the artifact's namespace is in the configured list.
// A match on a blocklist indicates the artifact should be denied.
type Blocklist struct{}

// Evaluate checks whether the artifact's namespace is in the blocked namespaces.
func (b Blocklist) Evaluate(req domain.AccessRequest, config map[string]any) (bool, string, error) {
	namespaces, err := extractNamespaces(config)
	if err != nil {
		return false, "", err
	}

	ns := req.Artifact.Namespace
	for _, blocked := range namespaces {
		if ns == blocked {
			return true, fmt.Sprintf("namespace %q is blocked", ns), nil
		}
	}

	return false, "", nil
}

func extractNamespaces(config map[string]any) ([]string, error) {
	raw, ok := config["namespaces"]
	if !ok {
		return nil, fmt.Errorf("missing required config key \"namespaces\"")
	}

	namespaces, ok := toStringSlice(raw)
	if !ok {
		return nil, fmt.Errorf("config key \"namespaces\" must be a list of strings")
	}

	return namespaces, nil
}
