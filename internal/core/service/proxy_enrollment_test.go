package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestParseProxyEnrollmentCSR(t *testing.T) {
	t.Parallel()
	valid := testCSRPEM(t, elliptic.P256(), false)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rsaKey)
	require.NoError(t, err)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rsaDER})
	badSignatureBlock, _ := pem.Decode(valid)
	badSignatureBlock.Bytes[len(badSignatureBlock.Bytes)-1] ^= 0xff
	badSignature := pem.EncodeToMemory(badSignatureBlock)

	tests := []struct {
		name    string
		csr     []byte
		wantErr bool
	}{
		{name: "valid P-256", csr: valid},
		{name: "empty", csr: nil, wantErr: true},
		{name: "malformed", csr: []byte("not pem"), wantErr: true},
		{name: "multiple blocks", csr: append(append([]byte(nil), valid...), valid...), wantErr: true},
		{name: "bad signature", csr: badSignature, wantErr: true},
		{name: "unsupported RSA", csr: rsaPEM, wantErr: true},
		{name: "unsupported P-384", csr: testCSRPEM(t, elliptic.P384(), false), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			der, err := ParseProxyEnrollmentCSR(tt.csr)
			if tt.wantErr {
				require.ErrorIs(t, err, domain.ErrProxyEnrollmentInvalid)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, der)
		})
	}
}

func TestProxyEnrollmentService_StartStoresOnlyDigests(t *testing.T) {
	t.Parallel()
	repository := &fakeProxyEnrollmentRepository{}
	service, err := NewProxyEnrollmentService(
		repository,
		repository,
		nil,
		nil,
		make([]byte, 32),
		ProxyEnrollmentSettings{
			VerificationURI: "https://example.test/activate",
			Validity:        10 * time.Minute,
			PollInterval:    5 * time.Second,
		},
	)
	require.NoError(t, err)

	started, err := service.Start(context.Background(), testCSRPEM(t, elliptic.P256(), true), "edge proxy")
	require.NoError(t, err)
	require.NotNil(t, repository.created)
	assert.Len(t, repository.created.DeviceCredentialDigest, 32)
	assert.Len(t, repository.created.UserCodeDigest, 32)
	assert.NotContains(t, string(repository.created.DeviceCredentialDigest), started.DeviceCredential)
	assert.NotContains(t, string(repository.created.UserCodeDigest), started.UserCode)
	assert.Regexp(t, regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`), started.UserCode)
	assert.Equal(t, "https://example.test/activate", started.VerificationURI)
}

func TestProxyEnrollmentService_ApproveGeneratesIdentityServerSide(t *testing.T) {
	t.Parallel()
	repository := &fakeProxyEnrollmentRepository{
		resolved: &domain.ProxyEnrollment{ID: "enrollment", CSRDER: []byte{1, 2, 3}},
	}
	issuer := &fakeWorkloadIssuer{}
	service, err := NewProxyEnrollmentService(
		repository, repository, allowTenantAuthorizer{}, issuer, make([]byte, 32),
		ProxyEnrollmentSettings{Validity: 10 * time.Minute, PollInterval: 5 * time.Second},
	)
	require.NoError(t, err)
	tenantID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	_, err = service.Approve(
		context.Background(),
		domain.AuthenticatedPrincipal{ID: "user-1"},
		"enrollment",
		"ABCD-EFGH",
		tenantID,
		"edge",
	)
	require.NoError(t, err)
	require.NotNil(t, repository.approval)
	assert.Regexp(
		t,
		`^spiffe://dependency-firewall/tenant/`+tenantID+`/proxy/[0-9a-f-]+$`,
		repository.approval.CanonicalIdentity,
	)
	assert.Equal(t, repository.approval.CanonicalIdentity, issuer.request.CanonicalIdentity)
	assert.Equal(t, []byte{1, 2, 3}, issuer.request.CSRDER)
}

func testCSRPEM(t *testing.T, curve elliptic.Curve, requestedIdentity bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker-controlled"}}
	if requestedIdentity {
		requestedURL, parseErr := url.Parse("spiffe://attacker/tenant/other")
		require.NoError(t, parseErr)
		template.URIs = []*url.URL{requestedURL}
		template.DNSNames = []string{"attacker.example"}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

type fakeProxyEnrollmentRepository struct {
	created  *domain.ProxyEnrollment
	resolved *domain.ProxyEnrollment
	approval *domain.ProxyEnrollmentApproval
}

func (r *fakeProxyEnrollmentRepository) CreateProxyEnrollment(
	_ context.Context,
	enrollment *domain.ProxyEnrollment,
) error {
	copy := *enrollment
	copy.ID = "enrollment"
	*enrollment = copy
	r.created = &copy
	return nil
}

func (r *fakeProxyEnrollmentRepository) ResolveProxyEnrollment(
	context.Context,
	string,
	[]byte,
	time.Time,
) (*domain.ProxyEnrollment, error) {
	return r.resolved, nil
}

func (r *fakeProxyEnrollmentRepository) ResolveProxyEnrollmentByUserCode(
	context.Context,
	[]byte,
	time.Time,
) (*domain.ProxyEnrollment, error) {
	return r.resolved, nil
}

func (r *fakeProxyEnrollmentRepository) ApproveProxyEnrollment(
	_ context.Context,
	_ string,
	_ []byte,
	approval domain.ProxyEnrollmentApproval,
	_ time.Time,
) (*domain.ProxyEnrollment, error) {
	r.approval = &approval
	return &domain.ProxyEnrollment{ID: "enrollment", Status: domain.ProxyEnrollmentApproved}, nil
}
func (*fakeProxyEnrollmentRepository) DenyProxyEnrollment(context.Context, string, []byte, string, time.Time) error {
	return nil
}

func (*fakeProxyEnrollmentRepository) PollProxyEnrollment(
	context.Context,
	[]byte,
	time.Time,
) (*domain.ProxyEnrollment, error) {
	return nil, errors.New("unused")
}

func (*fakeProxyEnrollmentRepository) GetProxyInstallation(
	context.Context,
	string,
	string,
) (*domain.ProxyInstallation, error) {
	return nil, errors.New("unused")
}

func (*fakeProxyEnrollmentRepository) ListProxyInstallations(
	context.Context,
	string,
) ([]domain.ProxyInstallation, error) {
	return nil, errors.New("unused")
}

func (*fakeProxyEnrollmentRepository) RenameProxyInstallation(
	context.Context,
	string,
	string,
	string,
) (*domain.ProxyInstallation, error) {
	return nil, errors.New("unused")
}

func (*fakeProxyEnrollmentRepository) RevokeProxyInstallation(
	context.Context,
	string,
	string,
	time.Time,
) (*domain.ProxyInstallation, error) {
	return nil, errors.New("unused")
}

type allowTenantAuthorizer struct{}

func (allowTenantAuthorizer) AuthorizeTenantApproval(context.Context, domain.AuthenticatedPrincipal, string) error {
	return nil
}

type fakeWorkloadIssuer struct {
	request domain.WorkloadCertificateRequest
}

func (i *fakeWorkloadIssuer) IssueWorkloadCertificate(
	_ context.Context,
	request domain.WorkloadCertificateRequest,
) (*domain.IssuedWorkloadCertificate, error) {
	i.request = request
	return &domain.IssuedWorkloadCertificate{
		CertificateChainPEM:  []byte("certificate"),
		ServerTrustBundlePEM: []byte("trust"),
		Serial:               "1",
		NotAfter:             time.Now().Add(time.Hour),
	}, nil
}
