// Package condition provides policy condition evaluators.
package condition

import (
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Condition evaluates whether a policy condition matches the request.
type Condition interface {
	Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (matched bool, reason string, err error)
}

var registry = map[domain.PolicyType]Condition{
	domain.PolicyTypeCVSSThreshold:    CVSSThreshold{},
	domain.PolicyTypeMinimumAge:       MinimumAge{},
	domain.PolicyTypeMaximumAge:       MaximumAge{},
	domain.PolicyTypeBlockMutableTag:  BlockMutableTag{},
	domain.PolicyTypeLicense:          License{},
	domain.PolicyTypeLicenseAllowlist: LicenseAllowlist{},
	domain.PolicyTypeAllowlist:        Allowlist{},
	domain.PolicyTypeBlocklist:        Blocklist{},
}

// ForType returns the condition evaluator for a policy type.
func ForType(policyType domain.PolicyType) (Condition, error) {
	c, ok := registry[policyType]
	if !ok {
		return nil, fmt.Errorf("unknown policy type %q", policyType)
	}
	return c, nil
}
