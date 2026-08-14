package domain

import "time"

// DataPlaneCredential is the persisted, scope-bound verifier metadata for a
// protocol credential. SecretDigest is never returned to API callers.
type DataPlaneCredential struct {
	ID             string
	TenantID       string
	OrganizationID string
	TeamID         string
	Name           string
	SecretDigest   string
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	CreatedBy      string
	LastUsedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// DataPlaneCredentialVerifier is the subset safe to ship in a runtime bundle.
type DataPlaneCredentialVerifier struct {
	ID             string
	TenantID       string
	OrganizationID string
	TeamID         string
	SecretDigest   string
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
}
