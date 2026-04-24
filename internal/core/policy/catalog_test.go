package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

func TestTypeCatalog_CoversSupportedPolicyTypes(t *testing.T) {
	descriptors := TypeCatalog()
	require.NotEmpty(t, descriptors)

	seen := make(map[domain.PolicyType]domain.PolicyTypeDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		_, duplicate := seen[descriptor.Type]
		assert.False(t, duplicate, "duplicate catalog entry for %q", descriptor.Type)
		seen[descriptor.Type] = descriptor

		assert.NotEmpty(t, descriptor.Summary, "summary for %q", descriptor.Type)
		assert.NotEmpty(t, descriptor.Description, "description for %q", descriptor.Type)
		assert.NotEmpty(t, descriptor.Help, "help for %q", descriptor.Type)
		assert.NotEmpty(t, descriptor.Example, "example for %q", descriptor.Type)
		assert.Positive(t, descriptor.CurrentSchemaVersion, "current schema version for %q", descriptor.Type)
		assert.NotEmpty(t, descriptor.SupportedSchemaVersions, "supported schema versions for %q", descriptor.Type)
		assert.Contains(t, descriptor.SupportedSchemaVersions, descriptor.CurrentSchemaVersion, "current schema version for %q", descriptor.Type)
		assert.NotEmpty(t, descriptor.SupportedActions, "supported actions for %q", descriptor.Type)

		_, err := newConfigForType(descriptor.Type, descriptor.CurrentSchemaVersion)
		require.NoError(t, err, "catalog type %q must have a config decoder", descriptor.Type)

		_, err = condition.ForType(descriptor.Type)
		require.NoError(t, err, "catalog type %q must have a condition evaluator", descriptor.Type)
	}

	require.Len(t, seen, len(knownPolicyTypes))
	for _, policyType := range knownPolicyTypes {
		_, ok := seen[policyType]
		assert.True(t, ok, "supported policy type %q is missing from the catalog", policyType)
	}
}
