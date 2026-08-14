package bundlegrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

const (
	ServiceName           = "dependencyfirewall.bundle.v1.BundleService"
	GetTenantBundleMethod = "/" + ServiceName + "/GetTenantBundle"
	TimeLayout            = "2006-01-02T15:04:05.999999999Z07:00"
)

type GetTenantBundleRequest struct {
	TenantID string `json:"tenant_id"`
}

type GetTenantBundleResponse struct {
	Bundle Bundle `json:"bundle"`
}

type Bundle struct {
	Tenant      BundleTenant     `json:"tenant"`
	TenantID    string           `json:"tenant_id"`
	Revision    string           `json:"revision"`
	GeneratedAt string           `json:"generated_at"`
	Policies    []BundlePolicy   `json:"policies"`
	Upstreams   []BundleUpstream `json:"upstreams"`
}

type BundleTenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type BundlePolicy struct {
	ID             string                  `json:"id"`
	TenantID       string                  `json:"tenant_id"`
	OrganizationID string                  `json:"organization_id,omitempty"`
	ScopeKind      domain.PolicyScope      `json:"scope_kind"`
	WaiverMode     domain.PolicyWaiverMode `json:"waiver_mode"`
	UpstreamID     string                  `json:"upstream_id,omitempty"`
	Name           string                  `json:"name"`
	Type           domain.PolicyType       `json:"type"`
	Action         domain.PolicyAction     `json:"action"`
	SchemaVersion  int                     `json:"schema_version"`
	Config         json.RawMessage         `json:"config"`
	Target         *domain.PolicyTarget    `json:"target,omitempty"`
	Priority       int                     `json:"priority"`
	Enabled        bool                    `json:"enabled"`
	Version        int                     `json:"version"`
	CreatedAt      string                  `json:"created_at"`
	UpdatedAt      string                  `json:"updated_at"`
}

type BundleUpstream struct {
	ID             string               `json:"id"`
	TenantID       string               `json:"tenant_id"`
	OrganizationID string               `json:"organization_id,omitempty"`
	TeamID         string               `json:"team_id,omitempty"`
	ScopeKind      domain.UpstreamScope `json:"scope_kind"`
	Name           string               `json:"name"`
	Ecosystem      domain.EcosystemType `json:"ecosystem"`
	BaseURL        string               `json:"base_url"`
	Capabilities   []string             `json:"capabilities"`
	Auth           *BundleUpstreamAuth  `json:"auth,omitempty"`
	CreatedAt      string               `json:"created_at"`
	UpdatedAt      string               `json:"updated_at"`
}

type BundleUpstreamAuth struct {
	Type      domain.UpstreamAuthType `json:"type"`
	Username  string                  `json:"username,omitempty"`
	Secret    string                  `json:"secret,omitempty"`
	UpdatedAt string                  `json:"updated_at,omitempty"`
}

// TenantIDFromRequest returns the tenant id carried by bundle gRPC requests.
func TenantIDFromRequest(req any) string {
	switch typed := req.(type) {
	case *GetTenantBundleRequest:
		return typed.TenantID
	default:
		return ""
	}
}

// FetchTenantBundleResponse invokes the remote bundle service and returns the wire DTO.
func FetchTenantBundleResponse(
	ctx context.Context,
	conn grpc.ClientConnInterface,
	tenantID string,
) (*GetTenantBundleResponse, error) {
	response := &GetTenantBundleResponse{}
	err := conn.Invoke(
		ctx,
		GetTenantBundleMethod,
		&GetTenantBundleRequest{TenantID: tenantID},
		response,
		grpc.ForceCodec(jsonCodec{}),
	)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// ToDomain converts a bundle wire DTO to the domain bundle representation.
func (b Bundle) ToDomain() (*domain.TenantBundle, error) {
	generatedAt, err := parseBundleTime(b.GeneratedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing bundle generated_at: %w", err)
	}
	tenant, err := b.Tenant.toDomain()
	if err != nil {
		return nil, err
	}

	result := &domain.TenantBundle{
		Tenant:      tenant,
		TenantID:    b.TenantID,
		Revision:    b.Revision,
		GeneratedAt: generatedAt,
		Policies:    make([]domain.Policy, 0, len(b.Policies)),
		Upstreams:   make([]domain.Upstream, 0, len(b.Upstreams)),
	}
	if result.TenantID == "" {
		result.TenantID = result.Tenant.ID
	}
	if result.Tenant.ID == "" {
		result.Tenant.ID = result.TenantID
	}

	for i := range b.Policies {
		policyDef, err := b.Policies[i].toDomain()
		if err != nil {
			return nil, err
		}
		result.Policies = append(result.Policies, *policyDef)
	}

	for i := range b.Upstreams {
		upstream, err := b.Upstreams[i].toDomain()
		if err != nil {
			return nil, err
		}
		result.Upstreams = append(result.Upstreams, *upstream)
	}

	return result, nil
}

func (t BundleTenant) toDomain() (domain.Tenant, error) {
	createdAt, err := parseBundleTime(t.CreatedAt)
	if err != nil {
		return domain.Tenant{}, fmt.Errorf("parsing tenant created_at: %w", err)
	}
	updatedAt, err := parseBundleTime(t.UpdatedAt)
	if err != nil {
		return domain.Tenant{}, fmt.Errorf("parsing tenant updated_at: %w", err)
	}

	return domain.Tenant{
		ID:        t.ID,
		Name:      t.Name,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

func (p BundlePolicy) toDomain() (*domain.Policy, error) {
	createdAt, err := parseBundleTime(p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing policy created_at: %w", err)
	}
	updatedAt, err := parseBundleTime(p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing policy updated_at: %w", err)
	}
	config, err := corepolicy.DecodeConfigJSON(p.Type, p.SchemaVersion, p.Config)
	if err != nil {
		return nil, fmt.Errorf("decoding policy config: %w", err)
	}
	if p.Target != nil {
		if err := p.Target.Validate(); err != nil {
			return nil, fmt.Errorf("validating policy target: %w", err)
		}
		p.Target.Normalize()
	}

	policyDef := &domain.Policy{
		ID:             p.ID,
		TenantID:       p.TenantID,
		OrganizationID: p.OrganizationID,
		ScopeKind:      p.ScopeKind,
		WaiverMode:     p.WaiverMode,
		UpstreamID:     p.UpstreamID,
		Name:           p.Name,
		Type:           p.Type,
		Action:         p.Action,
		SchemaVersion:  p.SchemaVersion,
		Config:         config,
		Target:         p.Target,
		Priority:       p.Priority,
		Enabled:        p.Enabled,
		Version:        p.Version,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}
	policyDef.NormalizeScope()
	if err := policyDef.ValidateScope(); err != nil {
		return nil, fmt.Errorf("validating policy scope: %w", err)
	}
	return policyDef, nil
}

func (u BundleUpstream) toDomain() (*domain.Upstream, error) {
	createdAt, err := parseBundleTime(u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream created_at: %w", err)
	}
	updatedAt, err := parseBundleTime(u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream updated_at: %w", err)
	}

	upstream := &domain.Upstream{
		ID:             u.ID,
		TenantID:       u.TenantID,
		OrganizationID: u.OrganizationID,
		TeamID:         u.TeamID,
		ScopeKind:      u.ScopeKind,
		Name:           u.Name,
		Ecosystem:      u.Ecosystem,
		BaseURL:        u.BaseURL,
		Capabilities:   domain.ParseUpstreamCapabilities(u.Capabilities),
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}
	upstream.NormalizeScope()
	if err := upstream.ValidateScope(); err != nil {
		return nil, fmt.Errorf("validating upstream scope: %w", err)
	}
	if u.Auth != nil && u.Auth.Type != "" && u.Auth.Type != domain.UpstreamAuthNone {
		authUpdatedAt, err := parseBundleTime(u.Auth.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing upstream auth updated_at: %w", err)
		}
		upstream.Auth = &domain.UpstreamAuth{
			Type:      u.Auth.Type,
			Username:  u.Auth.Username,
			Secret:    u.Auth.Secret,
			UpdatedAt: authUpdatedAt,
		}
	}
	return upstream, nil
}

func parseBundleTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(TimeLayout, raw)
}

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}
