package domain

import (
	"fmt"
	"slices"
)

// UpstreamCapability describes metadata or resolution features the firewall can
// rely on for one upstream.
type UpstreamCapability string

// The capability vocabulary. An upstream advertises which of these it can supply, and a policy scoped to that upstream
// is only accepted if the upstream still provides every capability the policy type requires. npm upstreams may offer
// publish time, licenses, vulnerability and Scorecard lookups; OCI upstreams offer manifest digest resolution.
const (
	UpstreamCapabilityPublishTime          UpstreamCapability = "publish_time"
	UpstreamCapabilityLicenses             UpstreamCapability = "licenses"
	UpstreamCapabilityVulnerabilityLookup  UpstreamCapability = "vulnerability_lookup"
	UpstreamCapabilityScorecardLookup      UpstreamCapability = "scorecard_lookup"
	UpstreamCapabilityManifestDigestLookup UpstreamCapability = "manifest_digest_lookup"
)

var allowedUpstreamCapabilities = map[EcosystemType][]UpstreamCapability{
	EcosystemNPM: {
		UpstreamCapabilityPublishTime,
		UpstreamCapabilityLicenses,
		UpstreamCapabilityVulnerabilityLookup,
		UpstreamCapabilityScorecardLookup,
	},
	EcosystemOCI: {
		UpstreamCapabilityManifestDigestLookup,
	},
}

var legacyDefaultUpstreamCapabilities = map[EcosystemType][][]UpstreamCapability{
	EcosystemNPM: {
		{
			UpstreamCapabilityPublishTime,
			UpstreamCapabilityLicenses,
			UpstreamCapabilityVulnerabilityLookup,
		},
	},
}

// AllowedUpstreamCapabilities returns the supported capability set for an ecosystem.
func AllowedUpstreamCapabilities(ecosystem EcosystemType) []UpstreamCapability {
	return append([]UpstreamCapability(nil), allowedUpstreamCapabilities[ecosystem]...)
}

// DefaultUpstreamCapabilities returns the recommended default capability set for an ecosystem.
func DefaultUpstreamCapabilities(ecosystem EcosystemType) []UpstreamCapability {
	return AllowedUpstreamCapabilities(ecosystem)
}

// NormalizeUpstreamCapabilities validates and canonicalizes the capability set for an ecosystem.
func NormalizeUpstreamCapabilities(
	ecosystem EcosystemType,
	capabilities []UpstreamCapability,
) ([]UpstreamCapability, error) {
	allowed := allowedUpstreamCapabilities[ecosystem]
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: unknown ecosystem %q", ErrUnsupportedUpstreamCapability, ecosystem)
	}
	if capabilities == nil {
		return DefaultUpstreamCapabilities(ecosystem), nil
	}

	set := make(map[UpstreamCapability]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if !slices.Contains(allowed, capability) {
			return nil, fmt.Errorf(
				"%w: capability %q is not supported for %s upstreams",
				ErrUnsupportedUpstreamCapability,
				capability,
				ecosystem,
			)
		}
		set[capability] = struct{}{}
	}

	normalized := make([]UpstreamCapability, 0, len(set))
	for _, capability := range allowed {
		if _, ok := set[capability]; ok {
			normalized = append(normalized, capability)
		}
	}
	return normalized, nil
}

// EffectiveUpstreamCapabilities upgrades legacy default capability profiles to
// the current default set while preserving explicitly customized profiles.
func EffectiveUpstreamCapabilities(
	ecosystem EcosystemType,
	capabilities []UpstreamCapability,
) []UpstreamCapability {
	if capabilities == nil {
		return DefaultUpstreamCapabilities(ecosystem)
	}
	for _, legacyDefaults := range legacyDefaultUpstreamCapabilities[ecosystem] {
		if slices.Equal(capabilities, legacyDefaults) {
			return DefaultUpstreamCapabilities(ecosystem)
		}
	}
	return append([]UpstreamCapability(nil), capabilities...)
}

// UpstreamCapabilityStrings converts capability values into plain strings for delivery or storage.
func UpstreamCapabilityStrings(capabilities []UpstreamCapability) []string {
	if len(capabilities) == 0 {
		return []string{}
	}
	result := make([]string, len(capabilities))
	for i := range capabilities {
		result[i] = string(capabilities[i])
	}
	return result
}

// ParseUpstreamCapabilities converts raw string values into typed capabilities.
func ParseUpstreamCapabilities(values []string) []UpstreamCapability {
	result := make([]UpstreamCapability, len(values))
	for i := range values {
		result[i] = UpstreamCapability(values[i])
	}
	return result
}

// EffectiveCapabilities returns the capability profile the application should
// use for compatibility and API responses.
func (u Upstream) EffectiveCapabilities() []UpstreamCapability {
	return EffectiveUpstreamCapabilities(u.Ecosystem, u.Capabilities)
}

// UpstreamSupports reports whether the upstream currently provides the capability.
func (u Upstream) UpstreamSupports(capability UpstreamCapability) bool {
	return slices.Contains(u.EffectiveCapabilities(), capability)
}
