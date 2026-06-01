package policy

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/policy/condition"
)

type configFactory func() domain.PolicyConfig

type policyDefinition struct {
	descriptor               domain.PolicyTypeDescriptor
	requiresExternalMetadata bool
	newConfigBySchema        map[int]configFactory
	configMatches            func(domain.PolicyConfig) bool
	conditionEvaluator       condition.Condition
}

type schemaConfig struct {
	version int
	factory configFactory
}

var policyDefinitionProviders = []func() policyDefinition{
	cvssThresholdPolicyDefinition,
	minimumAgePolicyDefinition,
	maximumAgePolicyDefinition,
	blockMutableTagPolicyDefinition,
	scorecardPolicyDefinition,
	licensePolicyDefinition,
	licenseAllowlistPolicyDefinition,
	allowlistPolicyDefinition,
	namespaceAllowlistPolicyDefinition,
	blocklistPolicyDefinition,
}

var policyDefinitions = collectPolicyDefinitions(policyDefinitionProviders)
var policyDefinitionsByType = indexPolicyDefinitions(policyDefinitions)

func collectPolicyDefinitions(providers []func() policyDefinition) []policyDefinition {
	definitions := make([]policyDefinition, 0, len(providers))
	for _, provider := range providers {
		definitions = append(definitions, provider())
	}
	return definitions
}

func definePolicy(
	descriptor domain.PolicyTypeDescriptor,
	conditionEvaluator condition.Condition,
	requiresExternalMetadata bool,
	configMatches func(domain.PolicyConfig) bool,
	schemaConfigs ...schemaConfig,
) policyDefinition {
	configs := make(map[int]configFactory, len(schemaConfigs))
	for _, schemaConfig := range schemaConfigs {
		configs[schemaConfig.version] = schemaConfig.factory
	}
	return policyDefinition{
		descriptor:               descriptor,
		requiresExternalMetadata: requiresExternalMetadata,
		newConfigBySchema:        configs,
		configMatches:            configMatches,
		conditionEvaluator:       conditionEvaluator,
	}
}

func configSchema(version int, factory configFactory) schemaConfig {
	return schemaConfig{version: version, factory: factory}
}

func indexPolicyDefinitions(definitions []policyDefinition) map[domain.PolicyType]policyDefinition {
	indexed := make(map[domain.PolicyType]policyDefinition, len(definitions))
	for _, definition := range definitions {
		policyType := definition.descriptor.Type
		if _, exists := indexed[policyType]; exists {
			panic(fmt.Sprintf("duplicate policy definition for type %q", policyType))
		}
		indexed[policyType] = definition
	}
	return indexed
}

func configTypeMatcher[T domain.PolicyConfig](config domain.PolicyConfig) bool {
	_, ok := config.(T)
	return ok
}

func policyDefinitionFor(policyType domain.PolicyType) (policyDefinition, bool) {
	definition, ok := policyDefinitionsByType[policyType]
	return definition, ok
}

func parsePolicyType(raw string) (domain.PolicyType, bool) {
	policyType := domain.PolicyType(raw)
	_, ok := policyDefinitionsByType[policyType]
	return policyType, ok
}

func conditionForType(policyType domain.PolicyType) (condition.Condition, error) {
	definition, ok := policyDefinitionFor(policyType)
	if !ok {
		return nil, fmt.Errorf("unknown policy type %q", policyType)
	}
	return definition.conditionEvaluator, nil
}

func newConfigForType(policyType domain.PolicyType, schemaVersion int) (domain.PolicyConfig, error) {
	definition, ok := policyDefinitionFor(policyType)
	if !ok {
		return nil, invalidPolicyf("unknown policy type %q", policyType)
	}
	factory, ok := definition.newConfigBySchema[schemaVersion]
	if !ok {
		return nil, fmt.Errorf(
			"%w: schema_version %d is not supported for policy type %q",
			domain.ErrUnsupportedPolicySchemaVersion,
			schemaVersion,
			policyType,
		)
	}
	return factory(), nil
}

func configTypeMatchesPolicy(policyType domain.PolicyType, config domain.PolicyConfig) bool {
	definition, ok := policyDefinitionFor(policyType)
	if !ok || definition.configMatches == nil {
		return false
	}
	return definition.configMatches(config)
}

func typeRequiresExternalMetadata(policyType domain.PolicyType) bool {
	definition, ok := policyDefinitionFor(policyType)
	if !ok {
		return false
	}
	return definition.requiresExternalMetadata
}

// RequiresExternalMetadata reports whether the policy type depends on external enrichment metadata.
func RequiresExternalMetadata(policyType domain.PolicyType) bool {
	return typeRequiresExternalMetadata(policyType)
}

// TypeCatalog returns the supported policy types and their help metadata.
func TypeCatalog() []domain.PolicyTypeDescriptor {
	result := make([]domain.PolicyTypeDescriptor, len(policyDefinitions))
	for i := range policyDefinitions {
		result[i] = cloneDescriptor(policyDefinitions[i].descriptor)
	}
	return result
}

func cloneDescriptor(descriptor domain.PolicyTypeDescriptor) domain.PolicyTypeDescriptor {
	copyValue := descriptor
	copyValue.SupportedActions = append([]domain.PolicyAction(nil), descriptor.SupportedActions...)
	copyValue.SupportedSchemaVersions = append([]int(nil), descriptor.SupportedSchemaVersions...)
	copyValue.SupportedEcosystems = append([]domain.EcosystemType(nil), descriptor.SupportedEcosystems...)
	copyValue.RequiredCapabilities = append([]domain.UpstreamCapability(nil), descriptor.RequiredCapabilities...)
	return copyValue
}
