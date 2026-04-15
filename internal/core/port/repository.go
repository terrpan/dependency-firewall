// Package port defines the interfaces that core services depend on.
// Infrastructure implements these interfaces.
package port

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// TenantRepository manages tenant persistence.
type TenantRepository interface {
	GetByID(ctx context.Context, id string) (*domain.Tenant, error)
	List(ctx context.Context) ([]domain.Tenant, error)
	Create(ctx context.Context, tenant *domain.Tenant) error
	Update(ctx context.Context, tenant *domain.Tenant) error
	Delete(ctx context.Context, id string) error
}

// PolicyRepository manages policy persistence.
type PolicyRepository interface {
	GetByID(ctx context.Context, tenantID, id string) (*domain.Policy, error)
	ListByTenant(ctx context.Context, tenantID string) ([]domain.Policy, error)
	Create(ctx context.Context, policy *domain.Policy) error
	Update(ctx context.Context, policy *domain.Policy) error
	Delete(ctx context.Context, tenantID, id string) error
}

// DecisionRepository records evaluation decisions.
type DecisionRepository interface {
	Record(ctx context.Context, decision *domain.Decision) error
	GetByArtifact(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error)
	ListByTenant(ctx context.Context, tenantID string, limit, offset int) ([]domain.Decision, error)
	HasRecentAllow(ctx context.Context, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error)
}

// UpstreamRepository manages upstream registry configs.
type UpstreamRepository interface {
	GetByID(ctx context.Context, tenantID, id string) (*domain.Upstream, error)
	GetByEcosystem(ctx context.Context, tenantID string, eco domain.EcosystemType) (*domain.Upstream, error)
	ListByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error)
	Create(ctx context.Context, upstream *domain.Upstream) error
	Update(ctx context.Context, upstream *domain.Upstream) error
	Delete(ctx context.Context, tenantID, id string) error
}
