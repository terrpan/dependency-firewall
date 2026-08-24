package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

const (
	maxProxyCSRPEMBytes = 16 << 10
	userCodeAlphabet    = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// ProxyEnrollmentSettings contains public enrollment metadata and lifecycle timing.
type ProxyEnrollmentSettings struct {
	VerificationURI   string
	PublicGRPCAddress string
	GRPCServerName    string
	Validity          time.Duration
	PollInterval      time.Duration
}

// ProxyEnrollmentService owns automatic proxy enrollment workflows.
type ProxyEnrollmentService struct {
	repository    port.ProxyEnrollmentRepository
	installations port.ProxyInstallationRepository
	authorizer    port.TenantApprovalAuthorizer
	issuer        port.WorkloadCertificateIssuer
	hmacKey       []byte
	settings      ProxyEnrollmentSettings
	now           func() time.Time
}

// NewProxyEnrollmentService constructs an enrollment service. The HMAC key must be exactly 32 bytes.
func NewProxyEnrollmentService(
	repository port.ProxyEnrollmentRepository,
	installations port.ProxyInstallationRepository,
	authorizer port.TenantApprovalAuthorizer,
	issuer port.WorkloadCertificateIssuer,
	hmacKey []byte,
	settings ProxyEnrollmentSettings,
) (*ProxyEnrollmentService, error) {
	if repository == nil || installations == nil {
		return nil, fmt.Errorf("proxy enrollment repositories are required")
	}
	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("proxy enrollment HMAC key must be exactly 32 bytes")
	}
	if settings.Validity <= 0 || settings.PollInterval <= 0 {
		return nil, fmt.Errorf("proxy enrollment validity and poll interval must be positive")
	}
	return &ProxyEnrollmentService{
		repository:    repository,
		installations: installations,
		authorizer:    authorizer,
		issuer:        issuer,
		hmacKey:       append([]byte(nil), hmacKey...),
		settings:      settings,
		now:           time.Now,
	}, nil
}

// StartedProxyEnrollment contains the only plaintext copies of the one-time credentials.
type StartedProxyEnrollment struct {
	Enrollment       *domain.ProxyEnrollment
	DeviceCredential string
	UserCode         string
	VerificationURI  string
}

// Start validates a CSR and creates a pending enrollment.
func (s *ProxyEnrollmentService) Start(
	ctx context.Context,
	csrPEM []byte,
	proposedName string,
) (*StartedProxyEnrollment, error) {
	csrDER, err := ParseProxyEnrollmentCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	deviceCredential, err := randomDeviceCredential()
	if err != nil {
		return nil, fmt.Errorf("generating proxy enrollment credential: %w", err)
	}
	userCode, err := randomUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating proxy enrollment user code: %w", err)
	}
	now := s.now().UTC()
	enrollment := &domain.ProxyEnrollment{
		DeviceCredentialDigest: s.digest(deviceCredential),
		UserCodeDigest:         s.digest(normalizeUserCode(userCode)),
		CSRDER:                 csrDER,
		ProposedName:           strings.TrimSpace(proposedName),
		Status:                 domain.ProxyEnrollmentPending,
		ExpiresAt:              now.Add(s.settings.Validity),
		PollInterval:           s.settings.PollInterval,
		NextPollAt:             now.Add(s.settings.PollInterval),
	}
	if err := s.repository.CreateProxyEnrollment(ctx, enrollment); err != nil {
		return nil, err
	}
	return &StartedProxyEnrollment{
		Enrollment:       enrollment,
		DeviceCredential: deviceCredential,
		UserCode:         userCode,
		VerificationURI:  s.settings.VerificationURI,
	}, nil
}

// Resolve returns safe enrollment details for a human-entered code.
func (s *ProxyEnrollmentService) Resolve(
	ctx context.Context,
	enrollmentID, userCode string,
) (*domain.ProxyEnrollment, error) {
	return s.repository.ResolveProxyEnrollment(ctx, enrollmentID, s.digest(normalizeUserCode(userCode)), s.now().UTC())
}

// ResolveUserCode returns safe pending details without requiring device-side state.
func (s *ProxyEnrollmentService) ResolveUserCode(
	ctx context.Context,
	userCode string,
) (*domain.ProxyEnrollment, error) {
	return s.repository.ResolveProxyEnrollmentByUserCode(ctx, s.digest(normalizeUserCode(userCode)), s.now().UTC())
}

// Approve authorizes a principal, issues a certificate, then atomically persists the winning approval.
func (s *ProxyEnrollmentService) Approve(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	enrollmentID, userCode, tenantID, installationName string,
) (*domain.ProxyEnrollment, error) {
	if strings.TrimSpace(principal.ID) == "" {
		return nil, domain.ErrUnauthenticated
	}
	if s.authorizer == nil {
		return nil, domain.ErrForbidden
	}
	if err := s.authorizer.AuthorizeTenantApproval(ctx, principal, tenantID); err != nil {
		return nil, err
	}
	if s.issuer == nil {
		return nil, fmt.Errorf("workload certificate issuer is not configured")
	}
	if _, err := uuid.Parse(strings.TrimSpace(tenantID)); err != nil {
		return nil, fmt.Errorf("%w: tenant id must be a UUID", domain.ErrProxyEnrollmentInvalid)
	}
	enrollment, err := s.Resolve(ctx, enrollmentID, userCode)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(installationName)
	if name == "" {
		return nil, fmt.Errorf("%w: installation name is required", domain.ErrProxyEnrollmentInvalid)
	}
	installationID := uuid.NewString()
	identityID := uuid.NewString()
	identity := fmt.Sprintf("spiffe://dependency-firewall/tenant/%s/proxy/%s", tenantID, installationID)
	issued, err := s.issuer.IssueWorkloadCertificate(ctx, domain.WorkloadCertificateRequest{
		CSRDER:            enrollment.CSRDER,
		CanonicalIdentity: identity,
	})
	if err != nil {
		return nil, fmt.Errorf("issuing proxy workload certificate: %w", err)
	}
	return s.repository.ApproveProxyEnrollment(
		ctx,
		enrollmentID,
		s.digest(normalizeUserCode(userCode)),
		domain.ProxyEnrollmentApproval{
			TenantID:             tenantID,
			InstallationID:       installationID,
			InstallationName:     name,
			IdentityID:           identityID,
			CanonicalIdentity:    identity,
			CertificateSerial:    issued.Serial,
			CertificateNotAfter:  issued.NotAfter,
			CertificateChainPEM:  issued.CertificateChainPEM,
			ServerTrustBundlePEM: issued.ServerTrustBundlePEM,
			PrincipalID:          principal.ID,
		},
		s.now().UTC(),
	)
}

// Deny rejects a pending enrollment after tenant-independent authentication of the human principal.
func (s *ProxyEnrollmentService) Deny(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	enrollmentID, userCode string,
) error {
	if strings.TrimSpace(principal.ID) == "" {
		return domain.ErrUnauthenticated
	}
	return s.repository.DenyProxyEnrollment(
		ctx,
		enrollmentID,
		s.digest(normalizeUserCode(userCode)),
		principal.ID,
		s.now().UTC(),
	)
}

// Poll returns pending/terminal state or atomically consumes an approved enrollment.
func (s *ProxyEnrollmentService) Poll(ctx context.Context, deviceCredential string) (*domain.ProxyEnrollment, error) {
	if strings.TrimSpace(deviceCredential) == "" {
		return nil, domain.ErrUnauthenticated
	}
	return s.repository.PollProxyEnrollment(ctx, s.digest(deviceCredential), s.now().UTC())
}

// GetInstallation returns one Tenant-owned proxy installation.
func (s *ProxyEnrollmentService) GetInstallation(
	ctx context.Context,
	tenantID, id string,
) (*domain.ProxyInstallation, error) {
	return s.installations.GetProxyInstallation(ctx, tenantID, id)
}

// ListInstallations returns all proxy installations for one Tenant.
func (s *ProxyEnrollmentService) ListInstallations(
	ctx context.Context,
	tenantID string,
) ([]domain.ProxyInstallation, error) {
	return s.installations.ListProxyInstallations(ctx, tenantID)
}

// RenameInstallation changes the display name of a live installation.
func (s *ProxyEnrollmentService) RenameInstallation(
	ctx context.Context,
	tenantID, id, name string,
) (*domain.ProxyInstallation, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: installation name is required", domain.ErrProxyEnrollmentInvalid)
	}
	return s.installations.RenameProxyInstallation(ctx, tenantID, id, strings.TrimSpace(name))
}

// RevokeInstallation permanently revokes an installation and its identities.
func (s *ProxyEnrollmentService) RevokeInstallation(
	ctx context.Context,
	tenantID, id string,
) (*domain.ProxyInstallation, error) {
	return s.installations.RevokeProxyInstallation(ctx, tenantID, id, s.now().UTC())
}

// AuthorizeTenantManagement applies the same provider-neutral Tenant permission to installation management.
func (s *ProxyEnrollmentService) AuthorizeTenantManagement(
	ctx context.Context,
	principal domain.AuthenticatedPrincipal,
	tenantID string,
) error {
	if strings.TrimSpace(principal.ID) == "" {
		return domain.ErrUnauthenticated
	}
	if s.authorizer == nil {
		return domain.ErrForbidden
	}
	return s.authorizer.AuthorizeTenantApproval(ctx, principal, tenantID)
}

func (s *ProxyEnrollmentService) digest(value string) []byte {
	mac := hmac.New(sha256.New, s.hmacKey)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

// ParseProxyEnrollmentCSR accepts one bounded PEM CSR with a verified P-256 key.
func ParseProxyEnrollmentCSR(csrPEM []byte) ([]byte, error) {
	if len(csrPEM) == 0 || len(csrPEM) > maxProxyCSRPEMBytes {
		return nil, fmt.Errorf(
			"%w: CSR must be between 1 and %d bytes",
			domain.ErrProxyEnrollmentInvalid,
			maxProxyCSRPEMBytes,
		)
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%w: exactly one PEM certificate request is required", domain.ErrProxyEnrollmentInvalid)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing CSR", domain.ErrProxyEnrollmentInvalid)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: invalid CSR signature", domain.ErrProxyEnrollmentInvalid)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != ellipticP256() {
		return nil, fmt.Errorf("%w: CSR must use ECDSA P-256", domain.ErrProxyEnrollmentInvalid)
	}
	return append([]byte(nil), csr.Raw...), nil
}

// ellipticP256 is isolated to make the accepted curve comparison explicit.
func ellipticP256() elliptic.Curve { return elliptic.P256() }

func randomDeviceCredential() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomUserCode() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i := range raw {
		raw[i] = userCodeAlphabet[int(raw[i])&31]
	}
	return string(raw[:4]) + "-" + string(raw[4:]), nil
}

func normalizeUserCode(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}

// DenyAllTenantApprovalAuthorizer is the safe default until a real human auth adapter is wired.
type DenyAllTenantApprovalAuthorizer struct{}

// AuthorizeTenantApproval denies every principal until a real adapter replaces it.
func (DenyAllTenantApprovalAuthorizer) AuthorizeTenantApproval(
	context.Context,
	domain.AuthenticatedPrincipal,
	string,
) error {
	return domain.ErrForbidden
}
