package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestValidatePolicies_AllowsSameNameInDifferentScopes(t *testing.T) {
	maxCVSS := 7.0
	base := domain.Policy{
		TenantID: "tenant-1",
		Name:     "block-critical",
		Type:     domain.PolicyTypeCVSSThreshold,
		Action:   domain.PolicyActionDeny,
		Config:   &domain.CVSSThresholdPolicyConfig{MaxCVSS: &maxCVSS},
	}
	accountPolicy := base
	organizationPolicy := base
	organizationPolicy.ScopeKind = domain.PolicyScopeOrganization
	organizationPolicy.OrganizationID = "organization-1"

	require.NoError(t, ValidatePolicies([]domain.Policy{accountPolicy, organizationPolicy}))
}
