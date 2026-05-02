package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type hashablePolicy struct {
	UpstreamID    string              `json:"upstream_id,omitempty"`
	Name          string              `json:"name"`
	Type          domain.PolicyType   `json:"type"`
	Action        domain.PolicyAction `json:"action"`
	SchemaVersion int                 `json:"schema_version"`
	Priority      int                 `json:"priority"`
	Enabled       bool                `json:"enabled"`
	Config        any                 `json:"config"`
}

// HashPolicies returns a canonical SHA-256 for the effective tenant policy set.
func HashPolicies(policies []domain.Policy) (string, error) {
	hashable := make([]hashablePolicy, len(policies))
	for i, p := range policies {
		hashable[i] = hashablePolicy{
			UpstreamID:    p.UpstreamID,
			Name:          p.Name,
			Type:          p.Type,
			Action:        p.Action,
			SchemaVersion: mustNormalizePolicySchemaVersion(p.Type, p.SchemaVersion),
			Priority:      p.Priority,
			Enabled:       p.Enabled,
			Config:        p.Config,
		}
	}

	sort.Slice(hashable, func(i, j int) bool {
		if hashable[i].Priority != hashable[j].Priority {
			return hashable[i].Priority < hashable[j].Priority
		}
		if hashable[i].Name != hashable[j].Name {
			return hashable[i].Name < hashable[j].Name
		}
		if hashable[i].UpstreamID != hashable[j].UpstreamID {
			return hashable[i].UpstreamID < hashable[j].UpstreamID
		}
		if hashable[i].Type != hashable[j].Type {
			return hashable[i].Type < hashable[j].Type
		}
		return hashable[i].Action < hashable[j].Action
	})

	payload, err := json.Marshal(hashable)
	if err != nil {
		return "", fmt.Errorf("marshalling canonical policy set: %w", err)
	}

	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func mustNormalizePolicySchemaVersion(policyType domain.PolicyType, version int) int {
	normalized, err := normalizeSchemaVersion(policyType, version)
	if err != nil {
		return version
	}
	return normalized
}
