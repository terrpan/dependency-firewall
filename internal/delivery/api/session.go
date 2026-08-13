package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
	"github.com/danielterry/dependency-firewall/internal/delivery/middleware"
)

type SessionHandler struct {
	sessions  *service.SessionService
	bootstrap *service.SessionBootstrapService
	logger    *slog.Logger
}

func NewSessionHandler(sessions *service.SessionService, logger *slog.Logger, bootstrap ...*service.SessionBootstrapService) *SessionHandler {
	handler := &SessionHandler{sessions: sessions, logger: logger}
	if len(bootstrap) > 0 {
		handler.bootstrap = bootstrap[0]
	}
	return handler
}

func (h *SessionHandler) RegisterHumaRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "get-session",
		Method:      http.MethodGet,
		Path:        "/api/v1/session",
		Summary:     "Get the active session",
		Description: "Returns the active account, local Organizations, and effective permissions. In disabled compatibility mode X-Tenant-ID selects the account.",
		Tags:        []string{"session"},
		Errors:      controlPlaneReadErrors(http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError),
	}, h.get)
	removeValidationResponse(api, "/api/v1/session", http.MethodGet)
	huma.Register(api, huma.Operation{
		OperationID: "bootstrap-session", Method: http.MethodPost, Path: "/api/v1/session/bootstrap",
		Summary:     "Bootstrap the active session",
		Description: "Synchronously establishes the local account and Principal projection after fresh provider membership verification.",
		Tags:        []string{"session"}, Errors: controlPlaneReadErrors(http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusInternalServerError),
	}, h.bootstrapSession)
	removeValidationResponse(api, "/api/v1/session/bootstrap", http.MethodPost)
}

type sessionInput struct {
	TenantID string `header:"X-Tenant-ID" doc:"Compatibility-mode Tenant identifier"`
}

type sessionOutput struct{ Body *SessionResponse }

type SessionResponse struct {
	Tenant             *TenantResponse               `json:"tenant"`
	Principal          SessionPrincipalResponse      `json:"principal"`
	TenantRole         domain.TenantRole             `json:"tenant_role"`
	Organizations      []SessionOrganizationResponse `json:"organizations"`
	AccountPermissions []domain.Permission           `json:"account_permissions"`
	CompatibilityMode  bool                          `json:"compatibility_mode"`
}

type SessionPrincipalResponse struct {
	ID          string                 `json:"id"`
	DisplayName string                 `json:"display_name"`
	Email       string                 `json:"email"`
	Status      domain.PrincipalStatus `json:"status"`
}

type SessionOrganizationResponse struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Status      domain.OrganizationStatus `json:"status"`
	IsDefault   bool                      `json:"is_default"`
	Role        domain.OrganizationRole   `json:"role"`
	Permissions []domain.Permission       `json:"permissions"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

func (h *SessionHandler) get(ctx context.Context, input *sessionInput) (*sessionOutput, error) {
	principal, authenticated := middleware.AuthenticatedPrincipalFromContext(ctx)
	var (
		session *domain.Session
		err     error
	)
	if authenticated {
		session, err = h.sessions.AuthenticatedSession(ctx, principal)
	} else {
		session, err = h.sessions.CompatibilitySession(ctx, input.TenantID)
	}
	if err != nil {
		if service.IsSessionTenantNotFound(err) {
			return nil, huma.Error404NotFound("account not found")
		}
		return nil, humaInternalError(ctx, h.logger, "getting session", err, "failed to get session")
	}
	return &sessionOutput{Body: toSessionResponse(session)}, nil
}

type bootstrapSessionInput struct{}

type bootstrapSessionOutput struct {
	Body *BootstrapSessionResponse
}

type BootstrapSessionResponse struct {
	Tenant     *TenantResponse          `json:"tenant"`
	Principal  SessionPrincipalResponse `json:"principal"`
	TenantRole domain.TenantRole        `json:"tenant_role"`
	Created    bool                     `json:"created"`
}

func (h *SessionHandler) bootstrapSession(ctx context.Context, _ *bootstrapSessionInput) (*bootstrapSessionOutput, error) {
	if h.bootstrap == nil {
		return nil, huma.Error403Forbidden("session bootstrap requires Clerk authentication mode")
	}
	identity, ok := middleware.VerifiedIdentityFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("valid bearer authentication required")
	}
	result, role, err := h.bootstrap.Bootstrap(ctx, identity)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrUnsupportedTenantRole):
			return nil, huma.Error403Forbidden("active account membership required")
		case errors.Is(err, domain.ErrSessionBootstrapConflict):
			return nil, huma.Error409Conflict("session bootstrap conflicted with an existing identity mapping")
		default:
			return nil, humaInternalError(ctx, h.logger, "bootstrapping session", err, "failed to bootstrap session")
		}
	}
	return &bootstrapSessionOutput{Body: &BootstrapSessionResponse{
		Tenant:     toTenantResponse(&result.Tenant),
		Principal:  SessionPrincipalResponse{ID: result.Principal.ID, DisplayName: result.Principal.DisplayName, Email: result.Principal.Email, Status: result.Principal.Status},
		TenantRole: role, Created: result.Created,
	}}, nil
}

func toSessionResponse(session *domain.Session) *SessionResponse {
	organizations := make([]SessionOrganizationResponse, len(session.Organizations))
	for index, membership := range session.Organizations {
		organization := membership.Organization
		organizations[index] = SessionOrganizationResponse{
			ID: organization.ID, Name: organization.Name, Status: organization.Status,
			IsDefault: organization.IsDefault, Role: membership.Role, Permissions: membership.Permissions,
			CreatedAt: organization.CreatedAt, UpdatedAt: organization.UpdatedAt,
		}
	}
	return &SessionResponse{
		Tenant: toTenantResponse(&session.Tenant),
		Principal: SessionPrincipalResponse{
			ID: session.Principal.ID, DisplayName: session.Principal.DisplayName,
			Email: session.Principal.Email, Status: session.Principal.Status,
		},
		TenantRole: session.TenantRole, Organizations: organizations,
		AccountPermissions: session.AccountPermissions, CompatibilityMode: session.CompatibilityMode,
	}
}
