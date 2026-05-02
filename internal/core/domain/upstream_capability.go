package domain

import (
	"fmt"
	"slices"
)

// UpstreamCapability describes metadata or resolution features the firewall can
// rely on for one upstream.
type UpstreamCapability string

const (
	UpstreamCapabilityPublishTime          UpstreamCapability = "publish_time"
	UpstreamCapabilityLicenses             UpstreamCapability = "licenses"
	UpstreamCapabilityVulnerabilityLookup  UpstreamCapability = "vulnerability_lookup"
	UpstreamCapabilityManifestDigestLookup UpstreamCapability = "manifest_digest_lookup"
)

var allowedUpstreamCapabilities = map[EcosystemType][]UpstreamCapability{
	EcosystemNPM: {
		UpstreamCapabilityPublishTime,
		UpstreamCapabilityLicenses,
		UpstreamCapabilityVulnerabilityLookup,
	},
	EcosystemOCI: {
		UpstreamCapabilityManifestDigestLookup,
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

// UpstreamSupports reports whether the upstream currently provides the capability.
func (u Upstream) UpstreamSupports(capability UpstreamCapability) bool {
	return slices.Contains(u.Capabilities, capability)
}
