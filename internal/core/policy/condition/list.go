package condition

import (
	"fmt"
	"slices"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Allowlist matches when the artifact's namespace is in the configured list.
// A match on an allowlist indicates the artifact should be allowed.
type Allowlist struct{}

// Evaluate checks whether the artifact's namespace is in the allowed namespaces.
func (a Allowlist) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.NamespaceListPolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("allowlist requires %T, got %T", &domain.NamespaceListPolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	ns := req.Artifact.Namespace
	if slices.Contains(typed.Namespaces, ns) {
		return true, fmt.Sprintf("namespace %q is allowed", ns), nil
	}

	return false, "", nil
}

// Blocklist matches when the artifact's namespace is in the configured list.
// A match on a blocklist indicates the artifact should be denied.
type Blocklist struct{}

// Evaluate checks whether the artifact's namespace is in the blocked namespaces.
func (b Blocklist) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.NamespaceListPolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("blocklist requires %T, got %T", &domain.NamespaceListPolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	ns := req.Artifact.Namespace
	if slices.Contains(typed.Namespaces, ns) {
		return true, fmt.Sprintf("namespace %q is blocked", ns), nil
	}

	return false, "", nil
}
