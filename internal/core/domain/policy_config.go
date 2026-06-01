package domain

// PolicyConfig is the typed configuration for a policy.
//
// Concrete implementations live in `policy_config_*.go` files alongside their
// shared validators and helper functions, one file per policy domain concept
// (cvss threshold, age, mutable tag, namespace list, scorecard, license).
type PolicyConfig interface {
	Validate() error
	DryRunEnabled() bool
}
