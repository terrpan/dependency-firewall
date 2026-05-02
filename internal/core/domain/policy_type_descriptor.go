package domain

// PolicyTypeDescriptor describes a supported policy type for API, CLI, and UI consumers.
type PolicyTypeDescriptor struct {
	Type                    PolicyType
	Summary                 string
	Description             string
	Help                    string
	CurrentSchemaVersion    int
	SupportedSchemaVersions []int
	SupportedActions        []PolicyAction
	SupportedEcosystems     []EcosystemType
	RequiredCapabilities    []UpstreamCapability
	Example                 string
}
