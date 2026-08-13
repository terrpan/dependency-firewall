package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/service"
)

type SessionHandler struct {
	sessions *service.SessionService
	logger   *slog.Logger
}

func NewSessionHandler(sessions *service.SessionService, logger *slog.Logger) *SessionHandler {
	return &SessionHandler{sessions: sessions, logger: logger}
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
	session, err := h.sessions.CompatibilitySession(ctx, input.TenantID)
	if err != nil {
		if service.IsSessionTenantNotFound(err) {
			return nil, huma.Error404NotFound("account not found")
		}
		return nil, humaInternalError(ctx, h.logger, "getting session", err, "failed to get session")
	}
	return &sessionOutput{Body: toSessionResponse(session)}, nil
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
