package domain

import "time"

type PrincipalStatus string

const (
	PrincipalStatusActive      PrincipalStatus = "active"
	PrincipalStatusSuspended   PrincipalStatus = "suspended"
	PrincipalStatusDeactivated PrincipalStatus = "deactivated"
)

// Principal is the provider-neutral local projection used for attribution and
// local Organization/Team membership. Email is informational, not an identity key.
type Principal struct {
	ID          string
	DisplayName string
	Email       string
	Status      PrincipalStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PrincipalIdentity links a Principal to one external identity subject.
type PrincipalIdentity struct {
	PrincipalID     string
	Provider        string
	ExternalSubject string
	CreatedAt       time.Time
}

// TenantIdentityLink maps an external account to the immutable local Tenant.
type TenantIdentityLink struct {
	TenantID   string
	Provider   string
	ExternalID string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type OrganizationStatus string

const (
	OrganizationStatusActive   OrganizationStatus = "active"
	OrganizationStatusArchived OrganizationStatus = "archived"
)

// Organization is the primary operational subdivision within a Tenant.
type Organization struct {
	ID        string
	TenantID  string
	Name      string
	Status    OrganizationStatus
	IsDefault bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type OrganizationRole string

const (
	OrganizationRoleAdmin         OrganizationRole = "admin"
	OrganizationRolePolicyManager OrganizationRole = "policy_manager"
	OrganizationRoleOperator      OrganizationRole = "operator"
	OrganizationRoleViewer        OrganizationRole = "viewer"
)

// OrganizationMembership grants a local role to a Principal in one Organization.
type OrganizationMembership struct {
	TenantID       string
	OrganizationID string
	PrincipalID    string
	Role           OrganizationRole
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Team limits where an Organization permission applies. Teams have no roles in v1.
type Team struct {
	ID             string
	TenantID       string
	OrganizationID string
	Name           string
	ArchivedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// TeamMembership associates a Principal with a Team without granting permissions.
type TeamMembership struct {
	TenantID       string
	OrganizationID string
	TeamID         string
	PrincipalID    string
	CreatedAt      time.Time
}
