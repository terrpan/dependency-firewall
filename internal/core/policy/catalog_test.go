package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
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
		assert.NotEmpty(t, descriptor.SupportedEcosystems, "supported ecosystems for %q", descriptor.Type)

		_, err := newConfigForType(descriptor.Type, descriptor.CurrentSchemaVersion)
		require.NoError(t, err, "catalog type %q must have a config decoder", descriptor.Type)

		_, err = conditionForType(descriptor.Type)
		require.NoError(t, err, "catalog type %q must have a condition evaluator", descriptor.Type)

		requiresMetadata := RequiresExternalMetadata(descriptor.Type)
		if descriptor.Type == domain.PolicyTypeCVSSThreshold ||
			descriptor.Type == domain.PolicyTypeMinimumAge ||
			descriptor.Type == domain.PolicyTypeMaximumAge ||
			descriptor.Type == domain.PolicyTypeScorecard ||
			descriptor.Type == domain.PolicyTypeLicense ||
			descriptor.Type == domain.PolicyTypeLicenseAllowlist {
			assert.True(t, requiresMetadata, "policy type %q should require external metadata", descriptor.Type)
		} else {
			assert.False(t, requiresMetadata, "policy type %q should not require external metadata", descriptor.Type)
		}
	}

	require.Len(t, seen, len(policyDefinitions))
	for i := range policyDefinitions {
		policyType := policyDefinitions[i].descriptor.Type
		_, ok := seen[policyType]
		assert.True(t, ok, "supported policy type %q is missing from the catalog", policyType)
	}
}

func TestValidateUpstreamCompatibility(t *testing.T) {
	npm := domain.Upstream{
		ID:           "u-npm",
		Name:         "npmjs",
		Ecosystem:    domain.EcosystemNPM,
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemNPM),
	}
	oci := domain.Upstream{
		ID:           "u-oci",
		Name:         "docker-hub",
		Ecosystem:    domain.EcosystemOCI,
		Capabilities: domain.DefaultUpstreamCapabilities(domain.EcosystemOCI),
	}
	npmWithoutLicenses := domain.Upstream{
		ID:           "u-npm-limited",
		Name:         "npm-limited",
		Ecosystem:    domain.EcosystemNPM,
		Capabilities: []domain.UpstreamCapability{domain.UpstreamCapabilityPublishTime},
	}

	require.NoError(t, ValidateUpstreamCompatibility(domain.PolicyTypeMinimumAge, npm))
	require.NoError(t, ValidateUpstreamCompatibility(domain.PolicyTypeBlockMutableTag, oci))
	require.NoError(t, ValidateUpstreamCompatibility(domain.PolicyTypeBlocklist, npm))
	require.NoError(t, ValidateUpstreamCompatibility(domain.PolicyTypeBlocklist, oci))

	err := ValidateUpstreamCompatibility(domain.PolicyTypeBlockMutableTag, npm)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrPolicyUpstreamIncompatible)
	assert.Contains(t, err.Error(), "only supports oci upstreams")

	err = ValidateUpstreamCompatibility(domain.PolicyTypeLicense, npmWithoutLicenses)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrPolicyUpstreamIncompatible)
	assert.Contains(t, err.Error(), "requires upstream capabilities licenses")
}
