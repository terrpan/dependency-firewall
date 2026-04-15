package domain

import "errors"

var (
	ErrTenantNotFound      = errors.New("tenant not found")
	ErrPolicyNotFound      = errors.New("policy not found")
	ErrPolicyViolation     = errors.New("policy violation")
	ErrUpstreamNotFound    = errors.New("upstream not found")
	ErrUpstreamUnavailable = errors.New("upstream unavailable")
	ErrEnrichmentFailed    = errors.New("enrichment failed")
	ErrArtifactNotFound    = errors.New("artifact not found")
	ErrInvalidArtifactRef  = errors.New("invalid artifact reference")
	ErrCacheMiss           = errors.New("cache miss")
	ErrUnauthorized        = errors.New("unauthorized")
)
