package bundlegrpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTenantIDFromRequest(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "tenant-1", TenantIDFromRequest(&GetTenantBundleRequest{TenantID: "tenant-1"}))
	assert.Empty(t, TenantIDFromRequest(struct{}{}))
}
