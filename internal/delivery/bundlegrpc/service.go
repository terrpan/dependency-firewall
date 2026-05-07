package bundlegrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

const serviceName = "dependencyfirewall.bundle.v1.BundleService"

type bundleService interface {
	GetTenantBundle(context.Context, *GetTenantBundleRequest) (*GetTenantBundleResponse, error)
}

// Server serves tenant bundles over gRPC.
type Server struct {
	provider port.TenantBundleProvider
}

// NewServer creates a new Server.
func NewServer(provider port.TenantBundleProvider) *Server {
	return &Server{provider: provider}
}

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
	ID            string              `json:"id"`
	TenantID      string              `json:"tenant_id"`
	UpstreamID    string              `json:"upstream_id,omitempty"`
	Name          string              `json:"name"`
	Type          domain.PolicyType   `json:"type"`
	Action        domain.PolicyAction `json:"action"`
	SchemaVersion int                 `json:"schema_version"`
	Config        json.RawMessage     `json:"config"`
	Priority      int                 `json:"priority"`
	Enabled       bool                `json:"enabled"`
	Version       int                 `json:"version"`
	CreatedAt     string              `json:"created_at"`
	UpdatedAt     string              `json:"updated_at"`
}

type BundleUpstream struct {
	ID           string               `json:"id"`
	TenantID     string               `json:"tenant_id"`
	Name         string               `json:"name"`
	Ecosystem    domain.EcosystemType `json:"ecosystem"`
	BaseURL      string               `json:"base_url"`
	Capabilities []string             `json:"capabilities"`
	CreatedAt    string               `json:"created_at"`
	UpdatedAt    string               `json:"updated_at"`
}

// Register registers the bundle service on the given gRPC registrar.
func (s *Server) Register(registrar grpc.ServiceRegistrar) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*bundleService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "GetTenantBundle",
				Handler:    s.getTenantBundleHandler,
			},
		},
	}, s)
}

// GetTenantBundle returns the current bundle for a tenant.
func (s *Server) GetTenantBundle(ctx context.Context, req *GetTenantBundleRequest) (*GetTenantBundleResponse, error) {
	if req == nil || req.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	bundle, err := s.provider.GetTenantBundle(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}

	response, err := toBundleResponse(bundle)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Server) getTenantBundleHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	req := &GetTenantBundleRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}

	if interceptor == nil {
		return srv.(bundleService).GetTenantBundle(ctx, req)
	}

	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/" + serviceName + "/GetTenantBundle",
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(bundleService).GetTenantBundle(ctx, req.(*GetTenantBundleRequest))
	}
	return interceptor(ctx, req, info, handler)
}

// GetTenantBundle invokes the remote bundle service using the given client connection.
func GetTenantBundle(ctx context.Context, conn grpc.ClientConnInterface, tenantID string) (*domain.TenantBundle, error) {
	response := &GetTenantBundleResponse{}
	err := conn.Invoke(
		ctx,
		"/"+serviceName+"/GetTenantBundle",
		&GetTenantBundleRequest{TenantID: tenantID},
		response,
		grpc.ForceCodec(jsonCodec{}),
	)
	if err != nil {
		return nil, err
	}

	return response.Bundle.toDomain()
}

func toBundleResponse(bundle *domain.TenantBundle) (*GetTenantBundleResponse, error) {
	tenant := bundle.Tenant
	if tenant.ID == "" {
		tenant.ID = bundle.TenantID
	}

	response := &GetTenantBundleResponse{
		Bundle: Bundle{
			Tenant: BundleTenant{
				ID:        tenant.ID,
				Name:      tenant.Name,
				CreatedAt: tenant.CreatedAt.UTC().Format(timeLayout),
				UpdatedAt: tenant.UpdatedAt.UTC().Format(timeLayout),
			},
			TenantID:    tenant.ID,
			Revision:    bundle.Revision,
			GeneratedAt: bundle.GeneratedAt.UTC().Format(timeLayout),
			Policies:    make([]BundlePolicy, 0, len(bundle.Policies)),
			Upstreams:   make([]BundleUpstream, 0, len(bundle.Upstreams)),
		},
	}

	for i := range bundle.Policies {
		config, err := json.Marshal(bundle.Policies[i].Config)
		if err != nil {
			return nil, fmt.Errorf("marshalling bundle policy config: %w", err)
		}

		response.Bundle.Policies = append(response.Bundle.Policies, BundlePolicy{
			ID:            bundle.Policies[i].ID,
			TenantID:      bundle.Policies[i].TenantID,
			UpstreamID:    bundle.Policies[i].UpstreamID,
			Name:          bundle.Policies[i].Name,
			Type:          bundle.Policies[i].Type,
			Action:        bundle.Policies[i].Action,
			SchemaVersion: bundle.Policies[i].SchemaVersion,
			Config:        config,
			Priority:      bundle.Policies[i].Priority,
			Enabled:       bundle.Policies[i].Enabled,
			Version:       bundle.Policies[i].Version,
			CreatedAt:     bundle.Policies[i].CreatedAt.UTC().Format(timeLayout),
			UpdatedAt:     bundle.Policies[i].UpdatedAt.UTC().Format(timeLayout),
		})
	}

	for i := range bundle.Upstreams {
		effectiveCapabilities := bundle.Upstreams[i].EffectiveCapabilities()
		response.Bundle.Upstreams = append(response.Bundle.Upstreams, BundleUpstream{
			ID:           bundle.Upstreams[i].ID,
			TenantID:     bundle.Upstreams[i].TenantID,
			Name:         bundle.Upstreams[i].Name,
			Ecosystem:    bundle.Upstreams[i].Ecosystem,
			BaseURL:      bundle.Upstreams[i].BaseURL,
			Capabilities: domain.UpstreamCapabilityStrings(effectiveCapabilities),
			CreatedAt:    bundle.Upstreams[i].CreatedAt.UTC().Format(timeLayout),
			UpdatedAt:    bundle.Upstreams[i].UpdatedAt.UTC().Format(timeLayout),
		})
	}

	return response, nil
}

const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

func (b Bundle) toDomain() (*domain.TenantBundle, error) {
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

	return &domain.Policy{
		ID:            p.ID,
		TenantID:      p.TenantID,
		UpstreamID:    p.UpstreamID,
		Name:          p.Name,
		Type:          p.Type,
		Action:        p.Action,
		SchemaVersion: p.SchemaVersion,
		Config:        config,
		Priority:      p.Priority,
		Enabled:       p.Enabled,
		Version:       p.Version,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}, nil
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

	return &domain.Upstream{
		ID:           u.ID,
		TenantID:     u.TenantID,
		Name:         u.Name,
		Ecosystem:    u.Ecosystem,
		BaseURL:      u.BaseURL,
		Capabilities: domain.ParseUpstreamCapabilities(u.Capabilities),
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}, nil
}

func parseBundleTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(timeLayout, raw)
}
