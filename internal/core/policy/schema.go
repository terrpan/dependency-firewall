package policy

import (
	"fmt"
	"slices"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func typeDescriptorFor(policyType domain.PolicyType) (domain.PolicyTypeDescriptor, bool) {
	definition, ok := policyDefinitionFor(policyType)
	if !ok {
		return domain.PolicyTypeDescriptor{}, false
	}
	return cloneDescriptor(definition.descriptor), true
}

func currentSchemaVersionForType(policyType domain.PolicyType) (int, error) {
	descriptor, ok := typeDescriptorFor(policyType)
	if !ok {
		return 0, invalidPolicyf("unknown policy type %q", policyType)
	}
	return descriptor.CurrentSchemaVersion, nil
}

// CurrentSchemaVersion returns the current schema version for a policy type.
func CurrentSchemaVersion(policyType domain.PolicyType) (int, error) {
	return currentSchemaVersionForType(policyType)
}

func normalizeSchemaVersion(policyType domain.PolicyType, version int) (int, error) {
	if version != 0 {
		return version, nil
	}
	return currentSchemaVersionForType(policyType)
}

// NormalizeSchemaVersion returns the explicit schema version or the current
// schema version for the given policy type when the input is zero.
func NormalizeSchemaVersion(policyType domain.PolicyType, version int) (int, error) {
	return normalizeSchemaVersion(policyType, version)
}

func validateSchemaVersion(policyType domain.PolicyType, version int) error {
	descriptor, ok := typeDescriptorFor(policyType)
	if !ok {
		return invalidPolicyf("unknown policy type %q", policyType)
	}
	if slices.Contains(descriptor.SupportedSchemaVersions, version) {
		return nil
	}
	return fmt.Errorf(
		"%w: schema_version %d is not supported for policy type %q; supported versions: %v",
		domain.ErrUnsupportedPolicySchemaVersion,
		version,
		policyType,
		descriptor.SupportedSchemaVersions,
	)
}

// SupportedSchemaVersions returns the supported schema versions for a policy type.
func SupportedSchemaVersions(policyType domain.PolicyType) ([]int, error) {
	descriptor, ok := typeDescriptorFor(policyType)
	if !ok {
		return nil, invalidPolicyf("unknown policy type %q", policyType)
	}
	return append([]int(nil), descriptor.SupportedSchemaVersions...), nil
}
