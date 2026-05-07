package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectiveUpstreamCapabilities_UpgradesLegacyDefaultProfile(t *testing.T) {
	assert.Equal(
		t,
		DefaultUpstreamCapabilities(EcosystemNPM),
		EffectiveUpstreamCapabilities(EcosystemNPM, []UpstreamCapability{
			UpstreamCapabilityPublishTime,
			UpstreamCapabilityLicenses,
			UpstreamCapabilityVulnerabilityLookup,
		}),
	)
}

func TestEffectiveUpstreamCapabilities_PreservesCustomizedProfile(t *testing.T) {
	customized := []UpstreamCapability{
		UpstreamCapabilityPublishTime,
		UpstreamCapabilityLicenses,
	}

	assert.Equal(t, customized, EffectiveUpstreamCapabilities(EcosystemNPM, customized))
}

func TestUpstreamSupports_UsesEffectiveCapabilities(t *testing.T) {
	upstream := Upstream{
		Ecosystem: EcosystemNPM,
		Capabilities: []UpstreamCapability{
			UpstreamCapabilityPublishTime,
			UpstreamCapabilityLicenses,
			UpstreamCapabilityVulnerabilityLookup,
		},
	}

	assert.True(t, upstream.UpstreamSupports(UpstreamCapabilityScorecardLookup))
}
