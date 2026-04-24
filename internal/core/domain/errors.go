package domain

import "errors"

var (
	ErrTenantNotFound                 = errors.New("tenant not found")
	ErrTenantNameConflict             = errors.New("tenant name already exists")
	ErrPolicyNotFound                 = errors.New("policy not found")
	ErrPolicyNameConflict             = errors.New("policy name already exists")
	ErrPolicyVersionNotFound          = errors.New("policy version not found")
	ErrDeprecatedPolicyConfig         = errors.New("deprecated stored policy config")
	ErrUnsupportedPolicySchemaVersion = errors.New("unsupported policy schema version")
	ErrInvalidPolicy                  = errors.New("invalid policy")
	ErrPolicyViolation                = errors.New("policy violation")
	ErrUpstreamNotFound               = errors.New("upstream not found")
	ErrUpstreamNameConflict           = errors.New("upstream name already exists")
	ErrUpstreamScopeConflict          = errors.New("upstream for ecosystem already exists")
	ErrUpstreamUnavailable            = errors.New("upstream unavailable")
	ErrEnrichmentFailed               = errors.New("enrichment failed")
	ErrArtifactNotFound               = errors.New("artifact not found")
	ErrInvalidArtifactRef             = errors.New("invalid artifact reference")
	ErrCacheMiss                      = errors.New("cache miss")
	ErrUnauthorized                   = errors.New("unauthorized")
)
