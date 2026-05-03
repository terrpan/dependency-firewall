package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func boolPtr(v bool) *bool { return &v }

func TestParseFile(t *testing.T) {
	validYAML := []byte(`
tenant_id: "tenant-abc-123"
policies:
  - name: block-critical
    type: cvss_threshold
    schema_version: 1
    action: deny
    priority: 10
    config:
      max_cvss: 7.0
    enabled: true
  - name: allow-internal
    type: allowlist
    schema_version: 1
    action: allow
    priority: 5
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

	t.Run("valid JSON parses correctly", func(t *testing.T) {
		pf, err := ParseFile([]byte(`{
  "tenant_id": "tenant-json",
  "policies": [
    {
      "name": "block-critical",
      "type": "cvss_threshold",
      "schema_version": 1,
      "action": "deny",
      "config": {
        "max_cvss": 7.0
      },
      "enabled": true
    }
  ]
}`))
		require.NoError(t, err)
		assert.Equal(t, "tenant-json", pf.TenantID)
		require.Len(t, pf.Policies, 1)
		assert.Equal(t, "block-critical", pf.Policies[0].Name)
		assert.Equal(t, 7.0, pf.Policies[0].Config["max_cvss"])
	})
}

func TestToDomainPolicies(t *testing.T) {
	t.Run("missing tenant_id returns error", func(t *testing.T) {
		pf := &PolicyFile{TenantID: "", Policies: []PolicyDef{{Name: "x", Type: "cvss_threshold", SchemaVersion: intPtr(1), Action: "deny"}}}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenant_id is required")
	})

	t.Run("invalid policy type returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{{Name: "x", Type: "unknown_type", SchemaVersion: intPtr(1), Action: "deny"}},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown policy type")
	})

	t.Run("explicit tenant override replaces YAML tenant_id", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "yaml-tenant",
			Policies: []PolicyDef{{
				Name:          "x",
				Type:          "cvss_threshold",
				SchemaVersion: intPtr(1),
				Action:        "deny",
				Config:        map[string]any{"max_cvss": 7.0},
			}},
		}
		policies, err := ToDomainPoliciesForTenant(pf, "header-tenant")
		require.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, "header-tenant", policies[0].TenantID)
	})

	t.Run("license policy type is accepted", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{
					Name:          "block-gpl",
					Type:          "license",
					SchemaVersion: intPtr(1),
					Action:        "deny",
					Config:        map[string]any{"licenses": []string{"GPL-3.0-only"}},
				},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, domain.PolicyTypeLicense, policies[0].Type)
	})

	t.Run("license allowlist policy type is accepted", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{
					Name:          "allow-approved-licenses",
					Type:          "license_allowlist",
					SchemaVersion: intPtr(1),
					Action:        "deny",
					Config:        map[string]any{"licenses": []string{"MIT", "Apache-2.0"}},
				},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, domain.PolicyTypeLicenseAllowlist, policies[0].Type)
	})

	t.Run("license allowlist schema v2 is accepted", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{
					Name:          "allow-approved-licenses",
					Type:          "license_allowlist",
					SchemaVersion: intPtr(2),
					Action:        "deny",
					Config: map[string]any{
						"licenses":                      []string{"MIT", "Apache-2.0"},
						"unlicensed_behavior":           "skip",
						"unavailable_metadata_behavior": "deny",
					},
				},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, domain.PolicyTypeLicenseAllowlist, policies[0].Type)
		assert.IsType(t, &domain.LicenseAllowlistPolicyConfigV2{}, policies[0].Config)
	})

	t.Run("namespace allowlist policy type is accepted", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{
					Name:          "allow-only-official-images",
					Type:          "namespace_allowlist",
					SchemaVersion: intPtr(1),
					Action:        "deny",
					Config:        map[string]any{"namespaces": []string{"library", "docker"}},
				},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, domain.PolicyTypeNamespaceAllowlist, policies[0].Type)
	})

	t.Run("tenant override allows files without tenant_id", func(t *testing.T) {
		pf := &PolicyFile{
			Policies: []PolicyDef{{
				Name:          "x",
				Type:          "cvss_threshold",
				SchemaVersion: intPtr(1),
				Action:        "deny",
				Config:        map[string]any{"max_cvss": 7.0},
			}},
		}
		policies, err := ToDomainPoliciesForTenant(pf, "header-tenant")
		require.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, "header-tenant", policies[0].TenantID)
	})

	t.Run("invalid action returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{{Name: "x", Type: "cvss_threshold", SchemaVersion: intPtr(1), Action: "block"}},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid action")
	})

	t.Run("missing name returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{{Name: "", Type: "cvss_threshold", SchemaVersion: intPtr(1), Action: "deny"}},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("default enabled to true when not specified", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{Name: "p1", Type: "cvss_threshold", SchemaVersion: intPtr(1), Action: "deny", Config: map[string]any{"max_cvss": 7.0}, Enabled: nil},
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
				{Name: "p1", Type: "cvss_threshold", SchemaVersion: intPtr(1), Action: "deny", Config: map[string]any{"max_cvss": 7.0}, Enabled: boolPtr(false)},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		assert.False(t, policies[0].Enabled)
	})

	t.Run("priority defaults to index when not specified", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{Name: "first", Type: "cvss_threshold", SchemaVersion: intPtr(1), Action: "deny", Config: map[string]any{"max_cvss": 7.0}},
				{Name: "second", Type: "allowlist", SchemaVersion: intPtr(1), Action: "allow", Config: map[string]any{"namespaces": []string{"internal"}}},
				{Name: "third", Type: "blocklist", SchemaVersion: intPtr(1), Action: "deny", Config: map[string]any{"namespaces": []string{"blocked"}}},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		require.Len(t, policies, 3)
		assert.Equal(t, 0, policies[0].Priority)
		assert.Equal(t, 1, policies[1].Priority)
		assert.Equal(t, 2, policies[2].Priority)
	})

	t.Run("explicit priority from YAML is used", func(t *testing.T) {
		p10 := 10
		p20 := 20
		p5 := 5
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{Name: "first", Type: "cvss_threshold", SchemaVersion: intPtr(1), Action: "deny", Priority: &p10, Config: map[string]any{"max_cvss": 7.0}},
				{Name: "second", Type: "allowlist", SchemaVersion: intPtr(1), Action: "allow", Priority: &p20, Config: map[string]any{"namespaces": []string{"internal"}}},
				{Name: "third", Type: "blocklist", SchemaVersion: intPtr(1), Action: "deny", Priority: &p5, Config: map[string]any{"namespaces": []string{"blocked"}}},
			},
		}
		policies, err := ToDomainPolicies(pf)
		require.NoError(t, err)
		require.Len(t, policies, 3)
		assert.Equal(t, 10, policies[0].Priority)
		assert.Equal(t, 20, policies[1].Priority)
		assert.Equal(t, 5, policies[2].Priority)
	})

	t.Run("unsupported config key returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{
					Name:          "x",
					Type:          "cvss_threshold",
					SchemaVersion: intPtr(1),
					Action:        "deny",
					Config:        map[string]any{"threshold": 7.0},
				},
			},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown field "threshold"`)
	})

	t.Run("invalid dry_run type returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{
				{
					Name:          "x",
					Type:          "cvss_threshold",
					SchemaVersion: intPtr(1),
					Action:        "deny",
					Config: map[string]any{
						"max_cvss": 7.0,
						"dry_run":  "true",
					},
				},
			},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `cannot unmarshal string into Go struct field`)
		assert.Contains(t, err.Error(), `dry_run`)
	})

	t.Run("missing schema_version returns error", func(t *testing.T) {
		pf := &PolicyFile{
			TenantID: "t1",
			Policies: []PolicyDef{{
				Name:   "x",
				Type:   "cvss_threshold",
				Action: "deny",
				Config: map[string]any{"max_cvss": 7.0},
			}},
		}
		_, err := ToDomainPolicies(pf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "schema_version is required")
	})
}
