package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// ValidateUpstreamCompatibility reports whether a policy type can run against an upstream.
func ValidateUpstreamCompatibility(policyType domain.PolicyType, upstream domain.Upstream) error {
	descriptor, ok := typeDescriptorFor(policyType)
	if !ok {
		return invalidPolicyf("unknown policy type %q", policyType)
	}
	if !slices.Contains(descriptor.SupportedEcosystems, upstream.Ecosystem) {
		return fmt.Errorf(
			"%w: policy type %q only supports %s upstreams",
			domain.ErrPolicyUpstreamIncompatible,
			policyType,
			formatEcosystems(descriptor.SupportedEcosystems),
		)
	}

	var missing []string
	for _, capability := range descriptor.RequiredCapabilities {
		if upstream.UpstreamSupports(capability) {
			continue
		}
		missing = append(missing, string(capability))
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"%w: policy type %q requires upstream capabilities %s",
			domain.ErrPolicyUpstreamIncompatible,
			policyType,
			strings.Join(missing, ", "),
		)
	}
	return nil
}

// SupportedPolicyTypesForUpstream lists the policy types an upstream can satisfy.
func SupportedPolicyTypesForUpstream(upstream domain.Upstream) []domain.PolicyType {
	result := make([]domain.PolicyType, 0, len(policyTypeCatalog))
	for _, descriptor := range policyTypeCatalog {
		if err := ValidateUpstreamCompatibility(descriptor.Type, upstream); err == nil {
			result = append(result, descriptor.Type)
		}
	}
	return result
}

func formatEcosystems(ecosystems []domain.EcosystemType) string {
	names := make([]string, len(ecosystems))
	for i := range ecosystems {
		names[i] = string(ecosystems[i])
	}
	return strings.Join(names, ", ")
}
