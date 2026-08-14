package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// BundleService builds proxy-ready tenant bundles from control-plane repositories.
type BundleService struct {
	tenants             tenantGetter
	policies            port.PolicyRepository
	upstreams           port.UpstreamRepository
	bundleUpstreams     port.BundleUpstreamRepository
	bundleCredentials   port.BundleCredentialRepository
	includeUpstreamAuth bool
}

type tenantGetter interface {
	GetByID(ctx context.Context, id string) (*domain.Tenant, error)
}

// NewBundleService creates a new BundleService.
func NewBundleService(
	tenants tenantGetter,
	policies port.PolicyRepository,
	upstreams port.UpstreamRepository,
	options ...BundleServiceOption,
) (*BundleService, error) {
	s := &BundleService{
		tenants:             tenants,
		policies:            policies,
		upstreams:           upstreams,
		includeUpstreamAuth: true,
	}
	for _, option := range options {
		option(s)
	}
	if s.bundleUpstreams == nil {
		return nil, fmt.Errorf("bundle upstream repository is required")
	}
	return s, nil
}

// BundleServiceOption customizes bundle construction.
type BundleServiceOption func(*BundleService)

// WithBundleUpstreamAuth controls whether authenticated upstream secrets may be included.
func WithBundleUpstreamAuth(include bool) BundleServiceOption {
	return func(s *BundleService) {
		s.includeUpstreamAuth = include
	}
}

// WithBundleUpstreamRepository uses a bundle-specific upstream repository that
// returns auth metadata without decrypting auth secrets.
func WithBundleUpstreamRepository(repo port.BundleUpstreamRepository) BundleServiceOption {
	return func(s *BundleService) {
		s.bundleUpstreams = repo
	}
}

// WithBundleCredentialRepository includes digest-only protocol verifiers.
func WithBundleCredentialRepository(repo port.BundleCredentialRepository) BundleServiceOption {
	return func(s *BundleService) { s.bundleCredentials = repo }
}

// GetTenantBundle returns the current proxy-ready bundle for a tenant.
func (s *BundleService) GetTenantBundle(ctx context.Context, tenantID string) (*domain.TenantBundle, error) {
	tenant, err := s.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("loading bundle tenant: %w", err)
	}
	if tenant == nil {
		return nil, fmt.Errorf("loading bundle tenant: %w", domain.ErrTenantNotFound)
	}

	policies, err := s.policies.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing bundle policies: %w", err)
	}

	upstreams, err := s.listBundleUpstreams(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing bundle upstreams: %w", err)
	}
	if !s.includeUpstreamAuth {
		for i := range upstreams {
			if upstreams[i].UpstreamAuthConfigured() {
				return nil, fmt.Errorf(
					"%w: authenticated upstreams cannot be bundled over insecure transport",
					domain.ErrUpstreamAuthTransportInsecure,
				)
			}
		}
	}
	var credentials []domain.DataPlaneCredentialVerifier
	if s.bundleCredentials != nil {
		credentials, err = s.bundleCredentials.ListVerifiersByTenant(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("listing bundle credential verifiers: %w", err)
		}
	}

	revision, err := bundleRevision(*tenant, policies, upstreams, credentials)
	if err != nil {
		return nil, fmt.Errorf("computing bundle revision: %w", err)
	}

	return &domain.TenantBundle{
		Tenant:      *tenant,
		TenantID:    tenant.ID,
		Revision:    revision,
		GeneratedAt: time.Now().UTC(),
		Policies:    policies,
		Upstreams:   upstreams,
		Credentials: credentials,
	}, nil
}

func (s *BundleService) listBundleUpstreams(ctx context.Context, tenantID string) ([]domain.Upstream, error) {
	if s.bundleUpstreams == nil {
		return nil, fmt.Errorf("bundle upstream repository is not configured")
	}
	return s.bundleUpstreams.ListBundleByTenant(ctx, tenantID)
}

// CachedBundleProvider refreshes bundles on demand and serves last-known-good state on failures.
type CachedBundleProvider struct {
	provider        port.TenantBundleProvider
	refreshInterval time.Duration
	logger          *slog.Logger

	mu                sync.RWMutex
	entries           map[string]cachedBundle
	lastSuccessTenant string
	lastSuccessRev    string
	lastSuccessAt     time.Time
	lastFailureTenant string
	lastFailureErr    string
	lastFailureAt     time.Time
}

type cachedBundle struct {
	bundle    *domain.TenantBundle
	refreshed time.Time
}

// NewCachedBundleProvider creates a new CachedBundleProvider.
func NewCachedBundleProvider(
	provider port.TenantBundleProvider,
	refreshInterval time.Duration,
	logger *slog.Logger,
) *CachedBundleProvider {
	return &CachedBundleProvider{
		provider:        provider,
		refreshInterval: refreshInterval,
		logger:          logger,
		entries:         make(map[string]cachedBundle),
	}
}

// GetTenantBundle returns a cached bundle when fresh, otherwise refreshes it.
func (p *CachedBundleProvider) GetTenantBundle(ctx context.Context, tenantID string) (*domain.TenantBundle, error) {
	entry, ok := p.load(tenantID)
	if ok && !p.shouldRefresh(entry.refreshed) {
		return cloneBundle(entry.bundle), nil
	}

	bundle, err := p.provider.GetTenantBundle(ctx, tenantID)
	if err == nil {
		p.store(tenantID, bundle)
		p.recordSuccess(tenantID, bundle)
		return cloneBundle(bundle), nil
	}

	p.recordFailure(tenantID, err)

	if ok {
		if p.logger != nil {
			p.logger.Warn("bundle refresh failed, serving last-known-good bundle",
				"tenant_id", tenantID,
				"revision", entry.bundle.Revision,
				"error", err,
			)
		}
		return cloneBundle(entry.bundle), nil
	}

	return nil, fmt.Errorf("%w: %v", domain.ErrBundleUnavailable, err)
}

// CheckStatus reports the current proxy bundle state for health responses.
func (p *CachedBundleProvider) CheckStatus(context.Context) ComponentStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	cachedCount := len(p.entries)

	switch {
	case p.lastFailureAt.After(p.lastSuccessAt):
		if cachedCount > 0 {
			return ComponentStatus{
				Status: "stale",
				Message: fmt.Sprintf(
					"serving last-known-good bundle cache (%d cached); last refresh failed for tenant %q: %s",
					cachedCount,
					p.lastFailureTenant,
					p.lastFailureErr,
				),
				Timestamp: p.lastFailureAt,
			}
		}
		return ComponentStatus{
			Status: "unavailable",
			Message: fmt.Sprintf(
				"no cached bundle available; last refresh failed for tenant %q: %s",
				p.lastFailureTenant,
				p.lastFailureErr,
			),
			Timestamp: p.lastFailureAt,
		}
	case !p.lastSuccessAt.IsZero():
		return ComponentStatus{
			Status: "ready",
			Message: fmt.Sprintf(
				"%d cached bundle(s); last refresh succeeded for tenant %q at revision %s",
				cachedCount,
				p.lastSuccessTenant,
				shortRevision(p.lastSuccessRev),
			),
			Timestamp: p.lastSuccessAt,
		}
	default:
		return ComponentStatus{
			Status:  "idle",
			Message: "no tenant bundles loaded yet",
		}
	}
}

func (p *CachedBundleProvider) shouldRefresh(refreshed time.Time) bool {
	if p.refreshInterval <= 0 {
		return true
	}
	return time.Since(refreshed) >= p.refreshInterval
}

func (p *CachedBundleProvider) load(tenantID string) (cachedBundle, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.entries[tenantID]
	return entry, ok
}

func (p *CachedBundleProvider) store(tenantID string, bundle *domain.TenantBundle) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries[tenantID] = cachedBundle{
		bundle:    cloneBundle(bundle),
		refreshed: time.Now().UTC(),
	}
}

func (p *CachedBundleProvider) recordSuccess(tenantID string, bundle *domain.TenantBundle) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastSuccessTenant = tenantID
	p.lastSuccessAt = time.Now().UTC()
	if bundle != nil {
		p.lastSuccessRev = bundle.Revision
	}
}

func (p *CachedBundleProvider) recordFailure(tenantID string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastFailureTenant = tenantID
	p.lastFailureErr = err.Error()
	p.lastFailureAt = time.Now().UTC()
}

type bundleHashInput struct {
	Tenant      bundleTenantHashInput                `json:"tenant"`
	Policies    []bundlePolicyHashInput              `json:"policies"`
	Upstreams   []bundleUpstreamHashInput            `json:"upstreams"`
	Credentials []domain.DataPlaneCredentialVerifier `json:"credentials"`
}

type bundleTenantHashInput struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type bundlePolicyHashInput struct {
	ID             string                  `json:"id"`
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
	UpdatedAt      time.Time               `json:"updated_at"`
}

type bundleUpstreamHashInput struct {
	ID             string                      `json:"id"`
	OrganizationID string                      `json:"organization_id,omitempty"`
	TeamID         string                      `json:"team_id,omitempty"`
	ScopeKind      domain.UpstreamScope        `json:"scope_kind"`
	Name           string                      `json:"name"`
	Ecosystem      domain.EcosystemType        `json:"ecosystem"`
	BaseURL        string                      `json:"base_url"`
	Capabilities   []domain.UpstreamCapability `json:"capabilities"`
	Auth           bundleUpstreamAuthHashInput `json:"auth"`
	UpdatedAt      time.Time                   `json:"updated_at"`
}

type bundleUpstreamAuthHashInput struct {
	Type      domain.UpstreamAuthType `json:"type"`
	Username  string                  `json:"username,omitempty"`
	UpdatedAt time.Time               `json:"updated_at"`
}

func bundleRevision(tenant domain.Tenant, policies []domain.Policy, upstreams []domain.Upstream, credentialSets ...[]domain.DataPlaneCredentialVerifier) (string, error) {
	var credentials []domain.DataPlaneCredentialVerifier
	if len(credentialSets) > 0 {
		credentials = credentialSets[0]
	}
	payload := bundleHashInput{
		Tenant: bundleTenantHashInput{
			ID:        tenant.ID,
			Name:      tenant.Name,
			CreatedAt: tenant.CreatedAt,
			UpdatedAt: tenant.UpdatedAt,
		},
		Policies:    make([]bundlePolicyHashInput, 0, len(policies)),
		Upstreams:   make([]bundleUpstreamHashInput, 0, len(upstreams)),
		Credentials: credentials,
	}

	for i := range policies {
		policyDef := policies[i]
		policyDef.NormalizeScope()
		config, err := json.Marshal(policyDef.Config)
		if err != nil {
			return "", fmt.Errorf("marshalling policy config: %w", err)
		}

		payload.Policies = append(payload.Policies, bundlePolicyHashInput{
			ID:             policyDef.ID,
			OrganizationID: policyDef.OrganizationID,
			ScopeKind:      policyDef.ScopeKind,
			WaiverMode:     policyDef.WaiverMode,
			UpstreamID:     policyDef.UpstreamID,
			Name:           policyDef.Name,
			Type:           policyDef.Type,
			Action:         policyDef.Action,
			SchemaVersion:  policyDef.SchemaVersion,
			Config:         config,
			Target:         policyDef.Target,
			Priority:       policyDef.Priority,
			Enabled:        policyDef.Enabled,
			Version:        policyDef.Version,
			UpdatedAt:      policyDef.UpdatedAt,
		})
	}

	for i := range upstreams {
		upstream := upstreams[i]
		upstream.NormalizeScope()
		auth := bundleUpstreamAuthHashInput{Type: domain.UpstreamAuthNone}
		if upstream.Auth != nil {
			auth = bundleUpstreamAuthHashInput{
				Type:      upstream.Auth.Type,
				Username:  upstream.Auth.Username,
				UpdatedAt: upstream.Auth.UpdatedAt,
			}
		}
		payload.Upstreams = append(payload.Upstreams, bundleUpstreamHashInput{
			ID:             upstream.ID,
			OrganizationID: upstream.OrganizationID,
			TeamID:         upstream.TeamID,
			ScopeKind:      upstream.ScopeKind,
			Name:           upstream.Name,
			Ecosystem:      upstream.Ecosystem,
			BaseURL:        upstream.BaseURL,
			Capabilities:   append([]domain.UpstreamCapability(nil), upstream.Capabilities...),
			Auth:           auth,
			UpdatedAt:      upstream.UpdatedAt,
		})
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshalling bundle payload: %w", err)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func cloneBundle(bundle *domain.TenantBundle) *domain.TenantBundle {
	if bundle == nil {
		return nil
	}

	cloned := &domain.TenantBundle{
		Tenant:      bundle.Tenant,
		TenantID:    bundle.TenantID,
		Revision:    bundle.Revision,
		GeneratedAt: bundle.GeneratedAt,
		Policies:    make([]domain.Policy, len(bundle.Policies)),
		Upstreams:   make([]domain.Upstream, len(bundle.Upstreams)),
		Credentials: append([]domain.DataPlaneCredentialVerifier(nil), bundle.Credentials...),
	}

	copy(cloned.Policies, bundle.Policies)
	for i := range bundle.Upstreams {
		cloned.Upstreams[i] = bundle.Upstreams[i]
		cloned.Upstreams[i].Capabilities = append([]domain.UpstreamCapability(nil), bundle.Upstreams[i].Capabilities...)
		if bundle.Upstreams[i].Auth != nil {
			auth := *bundle.Upstreams[i].Auth
			cloned.Upstreams[i].Auth = &auth
		}
	}

	return cloned
}

func shortRevision(revision string) string {
	if len(revision) <= 12 {
		return revision
	}
	return revision[:12]
}
