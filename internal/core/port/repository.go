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
	ListVersions(ctx context.Context, tenantID, policyID string, limit int) ([]domain.PolicyVersion, error)
	RollbackToVersion(ctx context.Context, tenantID, policyID string, version int) (*domain.Policy, error)
	Create(ctx context.Context, policy *domain.Policy) error
	Update(ctx context.Context, policy *domain.Policy) error
	Delete(ctx context.Context, tenantID, id string, force bool) error
}

// PolicyRevisionRepository records tenant policy-set revisions for audit.
type PolicyRevisionRepository interface {
	Create(ctx context.Context, revision *domain.PolicySetRevision) error
}

// DecisionRepository records evaluation decisions.
type DecisionRepository interface {
	Record(ctx context.Context, decision *domain.Decision) error
	GetByArtifact(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error)
	ListByTenant(ctx context.Context, tenantID string, limit, offset int, search string) ([]domain.Decision, error)
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

// BundleUpstreamRepository lists upstreams for bundle construction without
// decrypting auth secrets into domain memory.
type BundleUpstreamRepository interface {
	ListBundleByTenant(ctx context.Context, tenantID string) ([]domain.Upstream, error)
}

// UpstreamAuthSecretRewrapper decrypts one stored upstream auth secret and
// immediately passes it to a caller-supplied wrapping function.
type UpstreamAuthSecretRewrapper interface {
	RewrapUpstreamAuthSecret(ctx context.Context, tenantID, upstreamID string, wrap UpstreamAuthSecretWrapper) ([]byte, error)
}

// UpstreamAuthSecretWrapper encrypts or otherwise wraps a plaintext upstream auth secret.
type UpstreamAuthSecretWrapper func([]byte) ([]byte, error)
