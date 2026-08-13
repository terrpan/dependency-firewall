package api

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControlPlaneOperationPolicies_CoverEveryOperation(t *testing.T) {
	api := NewControlPlaneAPI(http.NewServeMux(), "test")
	logger := slog.Default()
	NewHealthHandler(nil, logger).RegisterHumaRoutes(api)
	NewSessionHandler(nil, logger).RegisterHumaRoutes(api)
	NewHierarchyHandler(nil, logger).RegisterHumaRoutes(api)
	NewTenantHandler(nil, logger).RegisterHumaRoutes(api)
	NewPolicyHandler(nil, logger).RegisterHumaRoutes(api)
	NewUpstreamHandler(nil, logger).RegisterHumaRoutes(api)
	NewEvaluationHandler(nil, logger).RegisterHumaRoutes(api)
	NewAuditHandler(nil, logger).RegisterHumaRoutes(api)
	NewCacheHandler(nil, logger).RegisterHumaRoutes(api)
	NewDependencyGraphHandler(nil, logger).RegisterHumaRoutes(api)

	seen := make(map[string]struct{})
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for path, item := range api.OpenAPI().Paths {
		for _, method := range methods {
			operation := pathOperation(item, method)
			if operation == nil {
				continue
			}
			policy, ok := ControlPlaneOperationPolicy(operation.OperationID)
			require.Truef(t, ok, "%s %s (%s) has no authorization policy", method, path, operation.OperationID)
			seen[operation.OperationID] = struct{}{}
			if operation.OperationID == "get-health" {
				assert.False(t, policy.AuthenticationRequired)
				continue
			}
			assert.True(t, policy.AuthenticationRequired, operation.OperationID)
			assert.NotEmpty(t, policy.Permission, operation.OperationID)
		}
	}

	for operationID := range controlPlaneOperationPolicies {
		assert.Containsf(t, seen, operationID, "stale authorization policy for %s", operationID)
	}
}
