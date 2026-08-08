package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestEvaluator_TargetDependencyContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		target       *domain.PolicyTarget
		context      *domain.DependencyContext
		wantOutcome  domain.DecisionOutcome
		wantWarnings int
	}{
		{
			name:        "direct context applies direct target",
			target:      &domain.PolicyTarget{DependencyScopes: []domain.DependencyScope{domain.DependencyScopeDirect}},
			context:     &domain.DependencyContext{Scope: domain.DependencyScopeDirect},
			wantOutcome: domain.DecisionDeny,
		},
		{
			name:        "transitive context skips direct target",
			target:      &domain.PolicyTarget{DependencyScopes: []domain.DependencyScope{domain.DependencyScopeDirect}},
			context:     &domain.DependencyContext{Scope: domain.DependencyScopeTransitive},
			wantOutcome: domain.DecisionAllow,
		},
		{
			name:        "matching dependency type applies target",
			target:      &domain.PolicyTarget{DependencyTypes: []domain.DependencyType{domain.DependencyTypePeer}},
			context:     &domain.DependencyContext{Scope: domain.DependencyScopeTransitive, DependencyTypes: []domain.DependencyType{domain.DependencyTypePeer}},
			wantOutcome: domain.DecisionDeny,
		},
		{
			name:         "unknown context defaults to warning",
			target:       &domain.PolicyTarget{DependencyScopes: []domain.DependencyScope{domain.DependencyScopeTransitive}},
			context:      &domain.DependencyContext{Scope: domain.DependencyScopeUnknown},
			wantOutcome:  domain.DecisionAllow,
			wantWarnings: 1,
		},
		{
			name:        "unknown context can deny",
			target:      &domain.PolicyTarget{DependencyScopes: []domain.DependencyScope{domain.DependencyScopeTransitive}, OnUnknown: domain.DependencyUnknownDeny},
			context:     &domain.DependencyContext{Scope: domain.DependencyScopeUnknown},
			wantOutcome: domain.DecisionDeny,
		},
	}

	evaluator := NewEvaluator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := domain.Policy{
				ID:            "policy-1",
				TenantID:      "tenant-1",
				Name:          "block package",
				Type:          domain.PolicyTypeBlocklist,
				Action:        domain.PolicyActionDeny,
				SchemaVersion: 1,
				Config: &domain.NamespaceListPolicyConfig{
					Namespaces: []string{"blocked"},
				},
				Target:   tt.target,
				Priority: 1,
				Enabled:  true,
			}
			if policy.Target != nil {
				policy.Target.Normalize()
			}
			decision := evaluator.Evaluate(domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Namespace: "blocked",
					Name:      "left-pad",
					Version:   "1.3.0",
				},
				DependencyContext: tt.context,
				Timestamp:         time.Now(),
			}, []domain.Policy{policy})

			assert.Equal(t, tt.wantOutcome, decision.Outcome)
			assert.Len(t, decision.Warnings, tt.wantWarnings)
		})
	}
}
