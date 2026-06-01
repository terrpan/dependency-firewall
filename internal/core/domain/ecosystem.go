package domain

// EcosystemType identifies the package ecosystem.
type EcosystemType string

const (
	EcosystemNPM EcosystemType = "npm"
	EcosystemOCI EcosystemType = "oci"
)
