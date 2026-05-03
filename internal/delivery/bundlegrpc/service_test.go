package bundlegrpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestBundleRoundTripPreservesTenantRuntime(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	bundle := &domain.TenantBundle{
		Tenant: domain.Tenant{
			ID:        "tenant-1",
			Name:      "Tenant One",
			CreatedAt: now.Add(-time.Hour),
			UpdatedAt: now,
		},
		TenantID:    "tenant-1",
		Revision:    "rev-1",
		GeneratedAt: now,
	}

	response, err := toBundleResponse(bundle)
	require.NoError(t, err)

	restored, err := response.Bundle.toDomain()
	require.NoError(t, err)
	assert.Equal(t, bundle.Tenant, restored.Tenant)
	assert.Equal(t, bundle.TenantID, restored.TenantID)
}

func TestBundleToDomainFallsBackToLegacyTenantID(t *testing.T) {
	t.Parallel()

	bundle, err := (Bundle{TenantID: "tenant-1"}).toDomain()
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", bundle.Tenant.ID)
	assert.Equal(t, "tenant-1", bundle.TenantID)
}
