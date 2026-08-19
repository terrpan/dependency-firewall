package domain

// EcosystemType identifies the package ecosystem.
type EcosystemType string

// Ecosystems the firewall can proxy and enforce policy for. The ecosystem selects the protocol adapter, the
// normalization rules for artifact identity, and which upstream capabilities and policy types are applicable.
const (
	EcosystemNPM EcosystemType = "npm"
	EcosystemOCI EcosystemType = "oci"
)
