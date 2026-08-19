package domain

import "errors"

// Sentinel errors shared across the core so that delivery adapters can map a failure to a protocol status and
// infrastructure can signal well-known conditions without leaking driver-specific error types. Compare them with
// errors.Is; the wrapped messages are safe to surface to callers.
var (
	ErrTenantNotFound                 = errors.New("tenant not found")
	ErrTenantNameConflict             = errors.New("tenant name already exists")
	ErrPolicyNotFound                 = errors.New("policy not found")
	ErrPolicyNameConflict             = errors.New("policy name already exists")
	ErrPolicyVersionNotFound          = errors.New("policy version not found")
	ErrPolicyDeleteEnabled            = errors.New("enabled policy cannot be deleted")
	ErrPolicyInUse                    = errors.New("policy is in use")
	ErrDeprecatedPolicyConfig         = errors.New("deprecated stored policy config")
	ErrUnsupportedPolicySchemaVersion = errors.New("unsupported policy schema version")
	ErrInvalidPolicy                  = errors.New("invalid policy")
	ErrPolicyViolation                = errors.New("policy violation")
	ErrPolicyUpstreamIncompatible     = errors.New("policy is not supported by upstream")
	ErrUpstreamNotFound               = errors.New("upstream not found")
	ErrUpstreamNameConflict           = errors.New("upstream name already exists")
	ErrUpstreamRegistryConflict       = errors.New("upstream registry already exists")
	ErrUpstreamInUse                  = errors.New("upstream is in use")
	ErrUnsupportedUpstreamCapability  = errors.New("unsupported upstream capability")
	ErrUpstreamPolicyConflict         = errors.New("upstream update conflicts with scoped policies")
	ErrUpstreamAuthInvalid            = errors.New("invalid upstream auth")
	ErrUpstreamAuthKeyUnavailable     = errors.New("upstream auth encryption key unavailable")
	ErrUpstreamAuthTransportInsecure  = errors.New("upstream auth requires secure bundle transport")
	ErrUpstreamUnavailable            = errors.New("upstream unavailable")
	ErrEnrichmentFailed               = errors.New("enrichment failed")
	ErrAuditUnavailable               = errors.New("audit logging unavailable")
	ErrBundleUnavailable              = errors.New("bundle unavailable")
	ErrArtifactNotFound               = errors.New("artifact not found")
	ErrInvalidArtifactRef             = errors.New("invalid artifact reference")
	ErrCacheMiss                      = errors.New("cache miss")
	ErrUnauthorized                   = errors.New("unauthorized")
)
