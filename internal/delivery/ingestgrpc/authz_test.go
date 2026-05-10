package ingestgrpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTenantIDFromRequest(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		req    any
		tenant string
	}{
		"record decision": {
			req:    &RecordDecisionRequest{Decision: Decision{TenantID: "tenant-1"}},
			tenant: "tenant-1",
		},
		"get decision": {
			req:    &GetDecisionByArtifactRequest{TenantID: "tenant-2"},
			tenant: "tenant-2",
		},
		"list decisions": {
			req:    &ListDecisionsByTenantRequest{TenantID: "tenant-3"},
			tenant: "tenant-3",
		},
		"has recent allow": {
			req:    &HasRecentAllowRequest{TenantID: "tenant-4"},
			tenant: "tenant-4",
		},
		"record audit": {
			req:    &RecordAuditEventRequest{Event: AuditEvent{TenantID: "tenant-5"}},
			tenant: "tenant-5",
		},
		"unknown": {
			req:    struct{}{},
			tenant: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.tenant, TenantIDFromRequest(tt.req))
		})
	}
}
