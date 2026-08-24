package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

// HumanPrincipalProvider extracts an authenticated provider-neutral principal from request context.
type HumanPrincipalProvider interface {
	PrincipalFromContext(context.Context) (domain.AuthenticatedPrincipal, error)
}

// AnonymousPrincipalProvider is the fail-closed default until an HTTP identity adapter is installed.
type AnonymousPrincipalProvider struct{}

// PrincipalFromContext always reports that authentication is absent.
func (AnonymousPrincipalProvider) PrincipalFromContext(context.Context) (domain.AuthenticatedPrincipal, error) {
	return domain.AuthenticatedPrincipal{}, domain.ErrUnauthenticated
}

// ProxyEnrollmentHandler serves machine enrollment, human activation, and installation management.
type ProxyEnrollmentHandler struct {
	service           *service.ProxyEnrollmentService
	principals        HumanPrincipalProvider
	logger            *slog.Logger
	publicAPIURL      string
	publicGRPCAddress string
	grpcServerName    string
}

// ProxyEnrollmentHandlerSettings contains public, non-secret enrollment endpoints.
type ProxyEnrollmentHandlerSettings struct {
	PublicAPIURL      string
	PublicGRPCAddress string
	GRPCServerName    string
}

// NewProxyEnrollmentHandler creates the HTTP enrollment boundary.
func NewProxyEnrollmentHandler(
	service *service.ProxyEnrollmentService,
	principals HumanPrincipalProvider,
	logger *slog.Logger,
	settings ProxyEnrollmentHandlerSettings,
) *ProxyEnrollmentHandler {
	if principals == nil {
		principals = AnonymousPrincipalProvider{}
	}
	return &ProxyEnrollmentHandler{
		service:           service,
		principals:        principals,
		logger:            logger,
		publicAPIURL:      settings.PublicAPIURL,
		publicGRPCAddress: settings.PublicGRPCAddress,
		grpcServerName:    settings.GRPCServerName,
	}
}

// RegisterHumaRoutes registers machine enrollment, human activation, and installation operations.
//
//nolint:funlen // keeping the related Huma operation declarations together makes the public contract auditable.
func (h *ProxyEnrollmentHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "get-proxy-enrollment-configuration",
		Method:        http.MethodGet,
		Path:          "/api/v1/proxy-enrollment-configuration",
		Summary:       "Get proxy enrollment configuration",
		Description:   "Returns the public enrollment API address for self-hosted proxy setup.",
		Tags:          []string{"proxy enrollment"},
		DefaultStatus: http.StatusOK,
	}, h.configuration)
	huma.Register(api, huma.Operation{
		OperationID:   "create-proxy-enrollment",
		Method:        http.MethodPost,
		Path:          "/api/v1/proxy-enrollments",
		Summary:       "Start proxy enrollment",
		Tags:          []string{"proxy enrollment"},
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  20 << 10,
		Errors: controlPlaneErrors(
			http.StatusBadRequest,
			http.StatusRequestEntityTooLarge,
			http.StatusInternalServerError,
		),
	}, h.start)
	huma.Register(api, huma.Operation{
		OperationID:  "poll-proxy-enrollment",
		Method:       http.MethodPost,
		Path:         "/api/v1/proxy-enrollments/token",
		Summary:      "Poll proxy enrollment",
		Tags:         []string{"proxy enrollment"},
		MaxBodyBytes: 1,
		Errors: controlPlaneErrors(
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusGone,
			http.StatusTooManyRequests,
			http.StatusInternalServerError,
		),
	}, h.poll)
	huma.Register(api, huma.Operation{
		OperationID: "resolve-proxy-enrollment", Method: http.MethodPost, Path: "/api/v1/proxy-enrollments/resolve",
		Summary: "Resolve an activation code", Tags: []string{"proxy enrollment"}, MaxBodyBytes: 2 << 10,
		Errors: controlPlaneErrors(http.StatusBadRequest, http.StatusGone, http.StatusInternalServerError),
	}, h.resolve)
	huma.Register(api, huma.Operation{
		OperationID:  "approve-proxy-enrollment",
		Method:       http.MethodPost,
		Path:         "/api/v1/proxy-enrollments/{id}/approve",
		Summary:      "Approve proxy enrollment",
		Tags:         []string{"proxy enrollment"},
		MaxBodyBytes: 4 << 10,
		Errors: controlPlaneErrors(
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusGone,
			http.StatusConflict,
			http.StatusInternalServerError,
		),
	}, h.approve)
	huma.Register(api, huma.Operation{
		OperationID:  "deny-proxy-enrollment",
		Method:       http.MethodPost,
		Path:         "/api/v1/proxy-enrollments/{id}/deny",
		Summary:      "Deny proxy enrollment",
		Tags:         []string{"proxy enrollment"},
		MaxBodyBytes: 2 << 10,
		Errors: controlPlaneErrors(
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusGone,
			http.StatusConflict,
			http.StatusInternalServerError,
		),
	}, h.deny)
	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-installations",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{tenant_id}/proxy-installations",
		Summary:     "List proxy installations",
		Tags:        []string{"proxy installations"},
		Errors:      controlPlaneReadErrors(http.StatusInternalServerError),
	}, h.listInstallations)
	huma.Register(api, huma.Operation{
		OperationID: "get-proxy-installation",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{tenant_id}/proxy-installations/{id}",
		Summary:     "Get proxy installation",
		Tags:        []string{"proxy installations"},
		Errors:      controlPlaneReadErrors(http.StatusNotFound, http.StatusInternalServerError),
	}, h.getInstallation)
	huma.Register(api, huma.Operation{
		OperationID:  "rename-proxy-installation",
		Method:       http.MethodPut,
		Path:         "/api/v1/tenants/{tenant_id}/proxy-installations/{id}",
		Summary:      "Rename proxy installation",
		Tags:         []string{"proxy installations"},
		MaxBodyBytes: 2 << 10,
		Errors: controlPlaneErrors(
			http.StatusBadRequest,
			http.StatusNotFound,
			http.StatusConflict,
			http.StatusInternalServerError,
		),
	}, h.renameInstallation)
	huma.Register(api, huma.Operation{
		OperationID: "revoke-proxy-installation",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{tenant_id}/proxy-installations/{id}",
		Summary:     "Revoke proxy installation",
		Tags:        []string{"proxy installations"},
		Errors:      controlPlaneErrors(http.StatusNotFound, http.StatusInternalServerError),
	}, h.revokeInstallation)
}

type proxyEnrollmentConfigurationResponse struct {
	PublicAPIURL string `json:"public_api_url"`
}

type proxyEnrollmentConfigurationOutput struct {
	Body proxyEnrollmentConfigurationResponse
}

func (h *ProxyEnrollmentHandler) configuration(
	context.Context,
	*struct{},
) (*proxyEnrollmentConfigurationOutput, error) {
	return &proxyEnrollmentConfigurationOutput{
		Body: proxyEnrollmentConfigurationResponse{PublicAPIURL: h.publicAPIURL},
	}, nil
}

type startProxyEnrollmentRequest struct {
	CSRPEM       string `json:"csr_pem"                 doc:"PEM encoded ECDSA P-256 certificate signing request"`
	ProposedName string `json:"proposed_name,omitempty"                                                           maxLength:"120"`
}

type startProxyEnrollmentInput struct{ Body startProxyEnrollmentRequest }

type startProxyEnrollmentResponse struct {
	EnrollmentID        string    `json:"enrollment_id"`
	DeviceCredential    string    `json:"device_credential"`
	UserCode            string    `json:"user_code"`
	VerificationURI     string    `json:"verification_uri"`
	ExpiresAt           time.Time `json:"expires_at"`
	PollIntervalSeconds int64     `json:"poll_interval_seconds"`
}

type startProxyEnrollmentOutput struct{ Body startProxyEnrollmentResponse }

type pollProxyEnrollmentInput struct {
	Authorization string `header:"Authorization" doc:"Bearer device credential"`
}

type pollProxyEnrollmentResponse struct {
	Error                     string `json:"error,omitempty"`
	TenantID                  string `json:"tenant_id,omitempty"`
	InstallationID            string `json:"installation_id,omitempty"`
	IdentityID                string `json:"identity_id,omitempty"`
	CanonicalIdentity         string `json:"canonical_identity,omitempty"`
	ClientCertificateChainPEM string `json:"client_certificate_chain_pem,omitempty"`
	ServerTrustBundlePEM      string `json:"server_trust_bundle_pem,omitempty"`
	GRPCAddress               string `json:"grpc_address,omitempty"`
	GRPCServerName            string `json:"grpc_server_name,omitempty"`
}

type pollProxyEnrollmentOutput struct {
	Status int
	Body   pollProxyEnrollmentResponse
}

type enrollmentCodeRequest struct {
	UserCode string `json:"user_code"`
}

type enrollmentCodeInput struct{ Body enrollmentCodeRequest }

type enrollmentIDCodeInput struct {
	ID   string `path:"id"`
	Body struct {
		UserCode string `json:"user_code"`
	}
}

type safeProxyEnrollmentResponse struct {
	ID             string                       `json:"id"`
	InstallationID string                       `json:"installation_id,omitempty"`
	ProposedName   string                       `json:"proposed_name,omitempty"`
	Status         domain.ProxyEnrollmentStatus `json:"status"`
	ExpiresAt      time.Time                    `json:"expires_at"`
}

type safeProxyEnrollmentOutput struct{ Body safeProxyEnrollmentResponse }

type approveProxyEnrollmentInput struct {
	ID   string `path:"id"`
	Body struct {
		UserCode         string `json:"user_code"`
		TenantID         string `json:"tenant_id"`
		InstallationName string `json:"installation_name"`
	}
}

type proxyInstallationResponse struct {
	ID               string                         `json:"id"`
	TenantID         string                         `json:"tenant_id"`
	Name             string                         `json:"name"`
	Status           domain.ProxyInstallationStatus `json:"status"`
	CreatedAt        time.Time                      `json:"created_at"`
	UpdatedAt        time.Time                      `json:"updated_at"`
	FirstConnectedAt *time.Time                     `json:"first_connected_at,omitempty"`
	RevokedAt        *time.Time                     `json:"revoked_at,omitempty"`
}

type proxyInstallationOutput struct{ Body proxyInstallationResponse }
type proxyInstallationListOutput struct{ Body []proxyInstallationResponse }
type proxyInstallationIDInput struct {
	TenantID string `path:"tenant_id"`
	ID       string `path:"id"`
}
type renameProxyInstallationInput struct {
	TenantID string `path:"tenant_id"`
	ID       string `path:"id"`
	Body     struct {
		Name string `json:"name"`
	}
}

func (h *ProxyEnrollmentHandler) start(
	ctx context.Context,
	input *startProxyEnrollmentInput,
) (*startProxyEnrollmentOutput, error) {
	started, err := h.service.Start(ctx, []byte(input.Body.CSRPEM), input.Body.ProposedName)
	if err != nil {
		if errors.Is(err, domain.ErrProxyEnrollmentInvalid) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		return nil, humaInternalError(
			ctx,
			h.logger,
			"starting proxy enrollment",
			err,
			"failed to start proxy enrollment",
		)
	}
	return &startProxyEnrollmentOutput{Body: startProxyEnrollmentResponse{
		EnrollmentID: started.Enrollment.ID, DeviceCredential: started.DeviceCredential,
		UserCode: started.UserCode, VerificationURI: started.VerificationURI,
		ExpiresAt:           started.Enrollment.ExpiresAt,
		PollIntervalSeconds: int64(started.Enrollment.PollInterval / time.Second),
	}}, nil
}

func (h *ProxyEnrollmentHandler) poll(
	ctx context.Context,
	input *pollProxyEnrollmentInput,
) (*pollProxyEnrollmentOutput, error) {
	credential, ok := bearerCredential(input.Authorization)
	if !ok {
		return nil, huma.Error401Unauthorized("device credential is required")
	}
	enrollment, err := h.service.Poll(ctx, credential)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrProxyEnrollmentPending):
			return &pollProxyEnrollmentOutput{
				Status: http.StatusAccepted,
				Body:   pollProxyEnrollmentResponse{Error: "authorization_pending"},
			}, nil
		case errors.Is(err, domain.ErrProxyEnrollmentSlowDown):
			return nil, huma.NewError(http.StatusTooManyRequests, "slow_down")
		case errors.Is(err, domain.ErrProxyEnrollmentDenied):
			return nil, huma.Error403Forbidden("access_denied")
		case errors.Is(err, domain.ErrProxyEnrollmentExpired):
			return nil, huma.NewError(http.StatusGone, "expired")
		case errors.Is(err, domain.ErrProxyEnrollmentConsumed):
			return nil, huma.NewError(http.StatusGone, "already_consumed")
		case errors.Is(err, domain.ErrProxyEnrollmentNotFound):
			return nil, huma.Error401Unauthorized("invalid device credential")
		default:
			return nil, humaInternalError(
				ctx,
				h.logger,
				"polling proxy enrollment",
				err,
				"failed to poll proxy enrollment",
			)
		}
	}
	return &pollProxyEnrollmentOutput{Status: http.StatusOK, Body: pollProxyEnrollmentResponse{
		TenantID: enrollment.TenantID, InstallationID: enrollment.InstallationID, IdentityID: enrollment.IdentityID,
		CanonicalIdentity:         enrollment.CanonicalIdentity,
		ClientCertificateChainPEM: string(enrollment.CertificateChainPEM),
		ServerTrustBundlePEM:      string(enrollment.ServerTrustBundlePEM),
		GRPCAddress:               h.publicGRPCAddress, GRPCServerName: h.grpcServerName,
	}}, nil
}

func (h *ProxyEnrollmentHandler) resolve(
	ctx context.Context,
	input *enrollmentCodeInput,
) (*safeProxyEnrollmentOutput, error) {
	enrollment, err := h.service.ResolveUserCode(ctx, input.Body.UserCode)
	if err != nil {
		return nil, h.enrollmentError(ctx, "resolving proxy enrollment", err)
	}
	return &safeProxyEnrollmentOutput{Body: safeEnrollment(enrollment)}, nil
}

func (h *ProxyEnrollmentHandler) approve(
	ctx context.Context,
	input *approveProxyEnrollmentInput,
) (*safeProxyEnrollmentOutput, error) {
	principal, err := h.principals.PrincipalFromContext(ctx)
	if err != nil {
		return nil, principalError(err)
	}
	enrollment, err := h.service.Approve(
		ctx,
		principal,
		input.ID,
		input.Body.UserCode,
		input.Body.TenantID,
		input.Body.InstallationName,
	)
	if err != nil {
		return nil, h.enrollmentError(ctx, "approving proxy enrollment", err)
	}
	return &safeProxyEnrollmentOutput{Body: safeEnrollment(enrollment)}, nil
}

func (h *ProxyEnrollmentHandler) deny(ctx context.Context, input *enrollmentIDCodeInput) (*struct{}, error) {
	principal, err := h.principals.PrincipalFromContext(ctx)
	if err != nil {
		return nil, principalError(err)
	}
	if err := h.service.Deny(ctx, principal, input.ID, input.Body.UserCode); err != nil {
		return nil, h.enrollmentError(ctx, "denying proxy enrollment", err)
	}
	return nil, nil
}

func (h *ProxyEnrollmentHandler) listInstallations(ctx context.Context, input *struct {
	TenantID string `path:"tenant_id"`
}) (*proxyInstallationListOutput, error) {
	if err := h.authorizeTenantManagement(ctx, input.TenantID); err != nil {
		return nil, err
	}
	installations, err := h.service.ListInstallations(ctx, input.TenantID)
	if err != nil {
		return nil, humaInternalError(
			ctx,
			h.logger,
			"listing proxy installations",
			err,
			"failed to list proxy installations",
		)
	}
	result := make([]proxyInstallationResponse, len(installations))
	for i := range installations {
		result[i] = installationResponse(&installations[i])
	}
	return &proxyInstallationListOutput{Body: result}, nil
}

func (h *ProxyEnrollmentHandler) getInstallation(
	ctx context.Context,
	input *proxyInstallationIDInput,
) (*proxyInstallationOutput, error) {
	if err := h.authorizeTenantManagement(ctx, input.TenantID); err != nil {
		return nil, err
	}
	installation, err := h.service.GetInstallation(ctx, input.TenantID, input.ID)
	if err != nil {
		return nil, h.installationError(ctx, "getting proxy installation", err)
	}
	return &proxyInstallationOutput{Body: installationResponse(installation)}, nil
}

func (h *ProxyEnrollmentHandler) renameInstallation(
	ctx context.Context,
	input *renameProxyInstallationInput,
) (*proxyInstallationOutput, error) {
	if err := h.authorizeTenantManagement(ctx, input.TenantID); err != nil {
		return nil, err
	}
	installation, err := h.service.RenameInstallation(ctx, input.TenantID, input.ID, input.Body.Name)
	if err != nil {
		return nil, h.installationError(ctx, "renaming proxy installation", err)
	}
	return &proxyInstallationOutput{Body: installationResponse(installation)}, nil
}

func (h *ProxyEnrollmentHandler) revokeInstallation(
	ctx context.Context,
	input *proxyInstallationIDInput,
) (*proxyInstallationOutput, error) {
	if err := h.authorizeTenantManagement(ctx, input.TenantID); err != nil {
		return nil, err
	}
	installation, err := h.service.RevokeInstallation(ctx, input.TenantID, input.ID)
	if err != nil {
		return nil, h.installationError(ctx, "revoking proxy installation", err)
	}
	return &proxyInstallationOutput{Body: installationResponse(installation)}, nil
}

func (h *ProxyEnrollmentHandler) authorizeTenantManagement(ctx context.Context, tenantID string) error {
	principal, err := h.principals.PrincipalFromContext(ctx)
	if err != nil {
		return principalError(err)
	}
	if err := h.service.AuthorizeTenantManagement(ctx, principal, tenantID); err != nil {
		return principalError(err)
	}
	return nil
}

func (h *ProxyEnrollmentHandler) enrollmentError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		return huma.Error401Unauthorized("authentication required")
	case errors.Is(err, domain.ErrForbidden):
		return huma.Error403Forbidden("not authorized for tenant")
	case errors.Is(err, domain.ErrProxyEnrollmentInvalid), errors.Is(err, domain.ErrProxyEnrollmentNotFound):
		return huma.Error400BadRequest("invalid enrollment or user code")
	case errors.Is(err, domain.ErrProxyEnrollmentExpired):
		return huma.NewError(http.StatusGone, "expired")
	case errors.Is(err, domain.ErrProxyEnrollmentConsumed):
		return huma.NewError(http.StatusGone, "already_consumed")
	case errors.Is(err, domain.ErrProxyEnrollmentDenied):
		return huma.Error403Forbidden("access_denied")
	case errors.Is(err, domain.ErrProxyEnrollmentConflict):
		return huma.Error409Conflict("enrollment state changed")
	case errors.Is(err, domain.ErrProxyInstallationNameConflict):
		return huma.Error409Conflict("proxy installation name already exists")
	default:
		return humaInternalError(ctx, h.logger, operation, err, "proxy enrollment operation failed")
	}
}

func (h *ProxyEnrollmentHandler) installationError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, domain.ErrProxyInstallationNotFound):
		return huma.Error404NotFound("proxy installation not found")
	case errors.Is(err, domain.ErrProxyInstallationNameConflict):
		return huma.Error409Conflict("proxy installation name already exists")
	case errors.Is(err, domain.ErrProxyEnrollmentInvalid):
		return huma.Error400BadRequest(err.Error())
	default:
		return humaInternalError(ctx, h.logger, operation, err, "proxy installation operation failed")
	}
}

func principalError(err error) error {
	if errors.Is(err, domain.ErrForbidden) {
		return huma.Error403Forbidden("not authorized for tenant")
	}
	return huma.Error401Unauthorized("authentication required")
}

func bearerCredential(header string) (string, bool) {
	prefix, credential, ok := strings.Cut(strings.TrimSpace(header), " ")
	return strings.TrimSpace(
			credential,
		), ok && strings.EqualFold(prefix, "Bearer") &&
			strings.TrimSpace(credential) != ""
}

func safeEnrollment(enrollment *domain.ProxyEnrollment) safeProxyEnrollmentResponse {
	return safeProxyEnrollmentResponse{
		ID:             enrollment.ID,
		InstallationID: enrollment.InstallationID,
		ProposedName:   enrollment.ProposedName,
		Status:         enrollment.Status,
		ExpiresAt:      enrollment.ExpiresAt,
	}
}

func installationResponse(installation *domain.ProxyInstallation) proxyInstallationResponse {
	return proxyInstallationResponse{
		ID: installation.ID, TenantID: installation.TenantID, Name: installation.Name, Status: installation.Status,
		CreatedAt: installation.CreatedAt, UpdatedAt: installation.UpdatedAt,
		FirstConnectedAt: installation.FirstConnectedAt, RevokedAt: installation.RevokedAt,
	}
}
