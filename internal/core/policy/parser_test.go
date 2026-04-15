package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFile(t *testing.T) {
	validYAML := []byte(`
tenant_id: "tenant-abc-123"
policies:
  - name: block-critical
    type: cvss_threshold
    action: deny
    config:
      max_cvss: 7.0
    enabled: true
  - name: allow-internal
    type: allowlist
    action: allow
    config:
      namespaces:
        - internal
`)

	t.Run("valid YAML parses correctly", func(t *testing.T) {
		pf, err := ParseFile(validYAML)
		require.NoError(t, err)

		assert.Equal(t, "tenant-abc-123", pf.TenantID)
		assert.Len(t, pf.Policies, 2)
		assert.Equal(t, "block-critical", pf.Policies[0].Name)
		assert.Equal(t, "cvss_threshold", pf.Policies[0].Type)
		assert.Equal(t, "deny", pf.Policies[0].Action)
		assert.Equal(t, 7.0, pf.Policies[0].Config["max_cvss"])
	})

	t.Run("invalid YAML returns error", func(t *testing.T) {
		_, err := ParseFile([]byte(":::invalid"))
		assert.Error(t, err)
	})
}

func TestToDomainPolicies(t *testing.T) {
	t.Run("missing tenant_id returns error", func(t *testing.T) {
		pf := &PolicyFile{TenantID: "", Policies: []PolicyDef{{Name: "x", Type: "cvss_threshold", Action: "deny"}}}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenant_id is required")
	})

	t.Run("invalid policy type returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{{Name: "x", Type: "unknown_type", Action: "deny"}},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown policy type")
	})

	t.Run("invalid action returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{{Name: "x", Type: "cvss_threshold", Action: "block"}},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid action")
	})

	t.Run("missing name returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{{Name: "", Type: "cvss_threshold", Action: "deny"}},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("default enabled to true when not specified", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{Name: "p1", Type: "cvss_threshold", Action: "deny", Enabled: nil},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		assert.True(t, policies[0].Enabled)
	})

	t.Run("enabled false is preserved", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{Name: "p1", Type: "cvss_threshold", Action: "deny", Enabled: new(false)},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		assert.False(t, policies[0].Enabled)
	})

	t.Run("priority assigned by order", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{Name: "first", Type: "cvss_threshold", Action: "deny"},
				{Name: "second", Type: "allowlist", Action: "allow"},
				{Name: "third", Type: "blocklist", Action: "deny"},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		require.Len(t, policies, 3)
		assert.Equal(t, 0, policies[0].Priority)
		assert.Equal(t, 1, policies[1].Priority)
		assert.Equal(t, 2, policies[2].Priority)
	})

	t.Run("deterministic ID from tenant and name", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{Name: "my-policy", Type: "cvss_threshold", Action: "deny"},
			},
		}
		p1, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		p2, err := ToDomainPolicies(pf)
		require.NoError(t, err)

		assert.Equal(t, p1[0].ID, p2[0].ID)
		assert.NotEmpty(t, p1[0].ID)
	})
}
