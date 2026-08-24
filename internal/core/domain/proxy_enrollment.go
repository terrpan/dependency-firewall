package domain

import "time"

// ProxyInstallationStatus is the lifecycle state of a self-hosted proxy installation.
type ProxyInstallationStatus string

const (
	// ProxyInstallationPending waits for the enrolled proxy to retrieve its certificate.
	ProxyInstallationPending ProxyInstallationStatus = "pending"
	// ProxyInstallationActive may authorize Tenant-scoped gRPC calls.
	ProxyInstallationActive ProxyInstallationStatus = "active"
	// ProxyInstallationRevoked is terminal and cannot authorize.
	ProxyInstallationRevoked ProxyInstallationStatus = "revoked"
)

// ProxyInstallation is a tenant-owned self-hosted proxy registration.
type ProxyInstallation struct {
	ID               string
	TenantID         string
	Name             string
	Status           ProxyInstallationStatus
	CreatedAt        time.Time
	UpdatedAt        time.Time
	FirstConnectedAt *time.Time
	RevokedAt        *time.Time
}

// WorkloadIdentity is a certificate identity owned by one proxy installation.
type WorkloadIdentity struct {
	ID                  string
	TenantID            string
	InstallationID      string
	CanonicalIdentity   string
	CertificateSerial   string
	CertificateNotAfter time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	RevokedAt           *time.Time
}

// ProxyEnrollmentStatus is the lifecycle state of a one-time enrollment.
type ProxyEnrollmentStatus string

const (
	// ProxyEnrollmentPending waits for human approval.
	ProxyEnrollmentPending ProxyEnrollmentStatus = "pending"
	// ProxyEnrollmentApproved has certificate material ready for one poll.
	ProxyEnrollmentApproved ProxyEnrollmentStatus = "approved"
	// ProxyEnrollmentDenied is a terminal human rejection.
	ProxyEnrollmentDenied ProxyEnrollmentStatus = "denied"
	// ProxyEnrollmentConsumed has delivered its certificate exactly once.
	ProxyEnrollmentConsumed ProxyEnrollmentStatus = "consumed"
	// ProxyEnrollmentExpired is terminal after its validity window.
	ProxyEnrollmentExpired ProxyEnrollmentStatus = "expired"
)

// ProxyEnrollment stores only digests of the bearer credential and user code.
type ProxyEnrollment struct {
	ID                     string
	DeviceCredentialDigest []byte
	UserCodeDigest         []byte
	CSRDER                 []byte
	ProposedName           string
	Status                 ProxyEnrollmentStatus
	ExpiresAt              time.Time
	PollInterval           time.Duration
	NextPollAt             time.Time
	TenantID               string
	InstallationID         string
	IdentityID             string
	CanonicalIdentity      string
	CertificateChainPEM    []byte
	ServerTrustBundlePEM   []byte
	ApprovingPrincipal     PrincipalRef
	DenyingPrincipal       PrincipalRef
	CreatedAt              time.Time
	UpdatedAt              time.Time
	ApprovedAt             *time.Time
	DeniedAt               *time.Time
	ConsumedAt             *time.Time
	ExpiredAt              *time.Time
}

// ProxyEnrollmentApproval contains the server-generated identity and issued certificate.
type ProxyEnrollmentApproval struct {
	TenantID             string
	InstallationID       string
	InstallationName     string
	IdentityID           string
	CanonicalIdentity    string
	CertificateSerial    string
	CertificateNotAfter  time.Time
	CertificateChainPEM  []byte
	ServerTrustBundlePEM []byte
	Principal            PrincipalRef
}

// WorkloadCertificateRequest contains only a verified public key and server-generated identity.
type WorkloadCertificateRequest struct {
	CSRDER            []byte
	CanonicalIdentity string
}

// IssuedWorkloadCertificate is safe to persist for one-time delivery; it never contains a private key.
type IssuedWorkloadCertificate struct {
	CertificateChainPEM  []byte
	ServerTrustBundlePEM []byte
	Serial               string
	NotAfter             time.Time
}

// WorkloadAuthorizationResult distinguishes unknown identities from known-but-denied identities.
type WorkloadAuthorizationResult struct {
	Known            bool
	Authorized       bool
	InstallationID   string
	FirstConnectedAt *time.Time
}
