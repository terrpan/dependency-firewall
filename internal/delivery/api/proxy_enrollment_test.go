package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

func TestProxyEnrollmentHandler_HumanApprovalAuthorization(t *testing.T) {
	t.Parallel()
	tenantID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tests := []struct {
		name       string
		principal  *domain.AuthenticatedPrincipal
		authorizer tenantApprovalAuthorizer
		wantStatus int
	}{
		{
			name:       "anonymous",
			authorizer: tenantApprovalAuthorizer{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "authenticated unauthorized",
			principal:  ptrPrincipal(apiTestPrincipal()),
			authorizer: tenantApprovalAuthorizer{err: domain.ErrForbidden},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "authorized provider-neutral principal",
			principal:  ptrPrincipal(apiTestPrincipal()),
			authorizer: tenantApprovalAuthorizer{},
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repository := &apiEnrollmentRepository{
				resolved: &domain.ProxyEnrollment{ID: "enrollment", CSRDER: []byte{1}},
			}
			enrollmentService, err := service.NewProxyEnrollmentService(
				repository, repository, tt.authorizer, apiWorkloadIssuer{}, make([]byte, 32),
				service.ProxyEnrollmentSettings{Validity: 10 * time.Minute, PollInterval: 5 * time.Second},
			)
			require.NoError(t, err)
			handler := NewProxyEnrollmentHandler(
				enrollmentService,
				slog.Default(),
				ProxyEnrollmentHandlerSettings{
					PublicAPIURL:      "https://firewall.example.com",
					PublicGRPCAddress: "grpc.example:443",
					GRPCServerName:    "grpc.example",
				},
			)
			input := &approveProxyEnrollmentInput{ID: "enrollment"}
			input.Body.UserCode = "ABCD-EFGH"
			input.Body.TenantID = tenantID
			input.Body.InstallationName = "edge"
			ctx := context.Background()
			if tt.principal != nil {
				ctx = middleware.ContextWithPrincipal(ctx, *tt.principal)
			}
			output, callErr := handler.approve(ctx, input)
			if tt.wantStatus == http.StatusOK {
				require.NoError(t, callErr)
				require.NotNil(t, output)
				assert.Equal(t, domain.ProxyEnrollmentApproved, output.Body.Status)
				return
			}
			require.Error(t, callErr)
			var statusErr huma.StatusError
			require.True(t, errors.As(callErr, &statusErr))
			assert.Equal(t, tt.wantStatus, statusErr.GetStatus())
		})
	}
}

func TestProxyEnrollmentHandler_ResolveRequiresAuthentication(t *testing.T) {
	t.Parallel()
	repository := &apiEnrollmentRepository{
		resolved: &domain.ProxyEnrollment{ID: "enrollment", Status: domain.ProxyEnrollmentPending},
	}
	enrollmentService, err := service.NewProxyEnrollmentService(
		repository,
		repository,
		tenantApprovalAuthorizer{},
		nil,
		make([]byte, 32),
		service.ProxyEnrollmentSettings{Validity: 10 * time.Minute, PollInterval: 5 * time.Second},
	)
	require.NoError(t, err)
	handler := NewProxyEnrollmentHandler(enrollmentService, slog.Default(), ProxyEnrollmentHandlerSettings{})
	input := &enrollmentCodeInput{Body: enrollmentCodeRequest{UserCode: "ABCD-EFGH"}}

	_, err = handler.resolve(context.Background(), input)
	require.Error(t, err)
	var statusErr huma.StatusError
	require.True(t, errors.As(err, &statusErr))
	assert.Equal(t, http.StatusUnauthorized, statusErr.GetStatus())

	ctx := middleware.ContextWithPrincipal(context.Background(), apiTestPrincipal())
	output, err := handler.resolve(ctx, input)
	require.NoError(t, err)
	assert.Equal(t, "enrollment", output.Body.ID)
}

func TestProxyEnrollmentHandler_ConfigurationReturnsOnlyPublicAPIURL(t *testing.T) {
	t.Parallel()
	handler := NewProxyEnrollmentHandler(nil, slog.Default(), ProxyEnrollmentHandlerSettings{
		PublicAPIURL: "https://firewall.example.com",
	})

	output, err := handler.configuration(context.Background(), &struct{}{})

	require.NoError(t, err)
	assert.Equal(t, "https://firewall.example.com", output.Body.PublicAPIURL)
}

func apiTestPrincipal() domain.AuthenticatedPrincipal {
	return domain.AuthenticatedPrincipal{Ref: domain.PrincipalRef{Issuer: "https://issuer.example", Subject: "user"}}
}

func ptrPrincipal(principal domain.AuthenticatedPrincipal) *domain.AuthenticatedPrincipal {
	return &principal
}

type tenantApprovalAuthorizer struct{ err error }

func (a tenantApprovalAuthorizer) Authorize(
	context.Context,
	domain.AuthenticatedPrincipal,
	string,
	domain.Permission,
) error {
	return a.err
}

type apiWorkloadIssuer struct{}

func (apiWorkloadIssuer) IssueWorkloadCertificate(
	context.Context,
	domain.WorkloadCertificateRequest,
) (*domain.IssuedWorkloadCertificate, error) {
	return &domain.IssuedWorkloadCertificate{
		CertificateChainPEM:  []byte("certificate"),
		ServerTrustBundlePEM: []byte("trust"),
		Serial:               "1",
		NotAfter:             time.Now().Add(time.Hour),
	}, nil
}

type apiEnrollmentRepository struct{ resolved *domain.ProxyEnrollment }

func (*apiEnrollmentRepository) CreateProxyEnrollment(context.Context, *domain.ProxyEnrollment) error {
	return nil
}

func (r *apiEnrollmentRepository) ResolveProxyEnrollment(
	context.Context,
	string,
	[]byte,
	time.Time,
) (*domain.ProxyEnrollment, error) {
	return r.resolved, nil
}

func (r *apiEnrollmentRepository) ResolveProxyEnrollmentByUserCode(
	context.Context,
	[]byte,
	time.Time,
) (*domain.ProxyEnrollment, error) {
	return r.resolved, nil
}

func (*apiEnrollmentRepository) ApproveProxyEnrollment(
	_ context.Context,
	_ string,
	_ []byte,
	approval domain.ProxyEnrollmentApproval,
	_ time.Time,
) (*domain.ProxyEnrollment, error) {
	return &domain.ProxyEnrollment{
		ID:             "enrollment",
		TenantID:       approval.TenantID,
		InstallationID: approval.InstallationID,
		Status:         domain.ProxyEnrollmentApproved,
	}, nil
}
func (*apiEnrollmentRepository) DenyProxyEnrollment(
	context.Context,
	string,
	[]byte,
	domain.PrincipalRef,
	time.Time,
) error {
	return nil
}

func (*apiEnrollmentRepository) PollProxyEnrollment(
	context.Context,
	[]byte,
	time.Time,
) (*domain.ProxyEnrollment, error) {
	return nil, errors.New("unused")
}

func (*apiEnrollmentRepository) GetProxyInstallation(
	context.Context,
	string,
	string,
) (*domain.ProxyInstallation, error) {
	return nil, errors.New("unused")
}
func (*apiEnrollmentRepository) ListProxyInstallations(context.Context, string) ([]domain.ProxyInstallation, error) {
	return nil, nil
}

func (*apiEnrollmentRepository) RenameProxyInstallation(
	context.Context,
	string,
	string,
	string,
) (*domain.ProxyInstallation, error) {
	return nil, errors.New("unused")
}

func (*apiEnrollmentRepository) RevokeProxyInstallation(
	context.Context,
	string,
	string,
	time.Time,
) (*domain.ProxyInstallation, error) {
	return nil, errors.New("unused")
}
