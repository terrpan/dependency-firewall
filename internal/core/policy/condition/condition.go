// Package condition provides policy condition evaluators.
package condition

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// Condition evaluates whether a policy condition matches the request.
type Condition interface {
	Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (matched bool, reason string, err error)
}
