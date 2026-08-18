package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func ptrFloat64(v float64) *float64  { return &v }
func ptrTime(t time.Time) *time.Time { return &t }
func ptrInt(v int) *int              { return &v }

func TestEvaluate(t *testing.T) {
	now := time.Now()
	recentPublish := now.Add(-24 * time.Hour) // 1 day ago

	baseReq := domain.AccessRequest{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "untrusted-registry",
			Name:      "some-package",
			Version:   "1.0.0",
		},
		Metadata: &domain.ArtifactMetadata{
			MaxCVSS:     ptrFloat64(9.0),
			PublishedAt: ptrTime(recentPublish),
		},
		Timestamp: now,
	}

	tests := []struct {
		name           string
		req            domain.AccessRequest
		policies       []domain.Policy
		wantOutcome    domain.DecisionOutcome
		wantReasonSub  string
		wantDenyCount  int
		wantAllowCount int
	}{
		{
			name: "single deny policy matches",
			req:  baseReq,
			policies: []domain.Policy{
				{
					ID: "p1", TenantID: "tenant-1", Name: "block-high-cvss",
					Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionDeny,
					Config: &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)}, Priority: 0, Enabled: true,
				},
			},
			wantOutcome:   domain.DecisionDeny,
			wantReasonSub: "CVSS score 9.0 at or above threshold 7.0",
			wantDenyCount: 1,
		},
		{
			name: "multiple deny policies match, first deny reason is user-facing",
			req:  baseReq,
			policies: []domain.Policy{
				{
					ID: "p1", TenantID: "tenant-1", Name: "block-high-cvss",
					Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionDeny,
					Config: &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)}, Priority: 0, Enabled: true,
				},
				{
					ID:       "p2",
					TenantID: "tenant-1",
					Name:     "block-untrusted",
					Type:     domain.PolicyTypeBlocklist,
					Action:   domain.PolicyActionDeny,
					Config: &domain.NamespaceListPolicyConfig{
						Namespaces: []string{"untrusted-registry"},
					},
					Priority: 1,
					Enabled:  true,
				},
			},
			wantOutcome:   domain.DecisionDeny,
			wantReasonSub: "CVSS score 9.0",
			wantDenyCount: 2,
		},
		{
			name: "only allow policies match",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemOCI,
					Namespace: "internal",
					Name:      "my-image",
					Version:   "v1.0",
				},
				Metadata:  &domain.ArtifactMetadata{},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID:       "p1",
					TenantID: "tenant-1",
					Name:     "allow-internal",
					Type:     domain.PolicyTypeAllowlist,
					Action:   domain.PolicyActionAllow,
					Config: &domain.NamespaceListPolicyConfig{
						Namespaces: []string{"internal"},
					},
					Priority: 0,
					Enabled:  true,
				},
			},
			wantOutcome:    domain.DecisionAllow,
			wantReasonSub:  "allowed",
			wantAllowCount: 1,
		},
		{
			name: "license policy denies configured blocked license",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "copyleft-package",
					Version:   "1.0.0",
				},
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"GPL-3.0-only"},
				},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID: "p-license", TenantID: "tenant-1", Name: "block-copyleft",
					Type: domain.PolicyTypeLicense, Action: domain.PolicyActionDeny,
					Config: &domain.LicensePolicyConfig{Licenses: []string{"GPL-3.0-only"}}, Priority: 0, Enabled: true,
				},
			},
			wantOutcome:   domain.DecisionDeny,
			wantReasonSub: `license "GPL-3.0-only"`,
			wantDenyCount: 1,
		},
		{
			name: "license allowlist denies unapproved license",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "copyleft-package",
					Version:   "1.0.0",
				},
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"GPL-3.0-only"},
				},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID:       "p-license-allowlist",
					TenantID: "tenant-1",
					Name:     "allow-approved-licenses",
					Type:     domain.PolicyTypeLicenseAllowlist,
					Action:   domain.PolicyActionDeny,
					Config: &domain.LicenseAllowlistPolicyConfig{
						Licenses: []string{"MIT", "Apache-2.0"},
					},
					Priority: 0,
					Enabled:  true,
				},
			},
			wantOutcome:   domain.DecisionDeny,
			wantReasonSub: `license "GPL-3.0-only" is not in the approved license list`,
			wantDenyCount: 1,
		},
		{
			name: "license allowlist denies missing metadata",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "unknown-license-package",
					Version:   "1.0.0",
				},
				Metadata:  nil,
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID: "p-license-allowlist", TenantID: "tenant-1", Name: "allow-approved-licenses",
					Type: domain.PolicyTypeLicenseAllowlist, Action: domain.PolicyActionDeny,
					Config: &domain.LicenseAllowlistPolicyConfig{Licenses: []string{"MIT"}}, Priority: 0, Enabled: true,
				},
			},
			wantOutcome:   domain.DecisionDeny,
			wantReasonSub: "license metadata is unavailable",
			wantDenyCount: 1,
		},
		{
			name: "license allowlist schema v2 can skip unavailable metadata",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "unknown-license-package",
					Version:   "1.0.0",
				},
				Metadata:  nil,
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID: "p-license-allowlist", TenantID: "tenant-1", Name: "allow-approved-licenses",
					Type: domain.PolicyTypeLicenseAllowlist, Action: domain.PolicyActionDeny,
					Config: &domain.LicenseAllowlistPolicyConfigV2{
						Licenses:                    []string{"MIT"},
						UnavailableMetadataBehavior: domain.LicenseAllowlistMissingBehaviorSkip,
					}, Priority: 0, Enabled: true,
				},
			},
			wantOutcome:   domain.DecisionAllow,
			wantReasonSub: "no matching policy",
		},
		{
			name: "license allowlist allows approved license set",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Name:      "approved-package",
					Version:   "1.0.0",
				},
				Metadata: &domain.ArtifactMetadata{
					Licenses: []string{"MIT", "Apache-2.0"},
				},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID:       "p-license-allowlist",
					TenantID: "tenant-1",
					Name:     "allow-approved-licenses",
					Type:     domain.PolicyTypeLicenseAllowlist,
					Action:   domain.PolicyActionDeny,
					Config: &domain.LicenseAllowlistPolicyConfig{
						Licenses: []string{"MIT", "Apache-2.0"},
					},
					Priority: 0,
					Enabled:  true,
				},
			},
			wantOutcome:   domain.DecisionAllow,
			wantReasonSub: "no matching policy",
		},
		{
			name: "namespace allowlist denies namespace outside approved set",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemOCI,
					Namespace: "random-org",
					Name:      "nginx",
					Version:   "1.25.3",
				},
				Metadata:  &domain.ArtifactMetadata{},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID:       "p-namespace-allowlist",
					TenantID: "tenant-1",
					Name:     "allow-only-approved-namespaces",
					Type:     domain.PolicyTypeNamespaceAllowlist,
					Action:   domain.PolicyActionDeny,
					Config: &domain.NamespaceListPolicyConfig{
						Namespaces: []string{"library", "docker"},
					},
					Priority: 0,
					Enabled:  true,
				},
			},
			wantOutcome:   domain.DecisionDeny,
			wantReasonSub: `namespace "random-org" is not in the approved namespace list`,
			wantDenyCount: 1,
		},
		{
			name: "namespace allowlist allows approved namespace",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemOCI,
					Namespace: "library",
					Name:      "nginx",
					Version:   "1.25.3",
				},
				Metadata:  &domain.ArtifactMetadata{},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID:       "p-namespace-allowlist",
					TenantID: "tenant-1",
					Name:     "allow-only-approved-namespaces",
					Type:     domain.PolicyTypeNamespaceAllowlist,
					Action:   domain.PolicyActionDeny,
					Config: &domain.NamespaceListPolicyConfig{
						Namespaces: []string{"library", "docker"},
					},
					Priority: 0,
					Enabled:  true,
				},
			},
			wantOutcome:   domain.DecisionAllow,
			wantReasonSub: "no matching policy",
		},
		{
			name: "mixed allow and deny, deny wins",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Namespace: "internal",
					Name:      "risky-package",
					Version:   "0.1.0",
				},
				Metadata: &domain.ArtifactMetadata{
					MaxCVSS: ptrFloat64(8.5),
				},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID:       "p1",
					TenantID: "tenant-1",
					Name:     "allow-internal",
					Type:     domain.PolicyTypeAllowlist,
					Action:   domain.PolicyActionAllow,
					Config: &domain.NamespaceListPolicyConfig{
						Namespaces: []string{"internal"},
					},
					Priority: 0,
					Enabled:  true,
				},
				{
					ID: "p2", TenantID: "tenant-1", Name: "block-high-cvss",
					Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionDeny,
					Config: &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)}, Priority: 1, Enabled: true,
				},
			},
			wantOutcome:    domain.DecisionDeny,
			wantReasonSub:  "CVSS score 8.5",
			wantDenyCount:  1,
			wantAllowCount: 1,
		},
		{
			name:          "no policies, default allow",
			req:           baseReq,
			policies:      nil,
			wantOutcome:   domain.DecisionAllow,
			wantReasonSub: "no matching policy",
		},
		{
			name: "disabled policies are skipped",
			req:  baseReq,
			policies: []domain.Policy{
				{
					ID: "p1", TenantID: "tenant-1", Name: "block-high-cvss",
					Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionDeny,
					Config: &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)}, Priority: 0, Enabled: false,
				},
			},
			wantOutcome:   domain.DecisionAllow,
			wantReasonSub: "no matching policy",
		},
		{
			name: "priority ordering is respected",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Namespace: "untrusted-registry",
					Name:      "some-package",
					Version:   "1.0.0",
				},
				Metadata: &domain.ArtifactMetadata{
					MaxCVSS: ptrFloat64(9.0),
				},
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID:       "p2",
					TenantID: "tenant-1",
					Name:     "block-untrusted",
					Type:     domain.PolicyTypeBlocklist,
					Action:   domain.PolicyActionDeny,
					Config: &domain.NamespaceListPolicyConfig{
						Namespaces: []string{"untrusted-registry"},
					},
					Priority: 5,
					Enabled:  true,
				},
				{
					ID: "p1", TenantID: "tenant-1", Name: "block-high-cvss",
					Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionDeny,
					Config: &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)}, Priority: 0, Enabled: true,
				},
			},
			wantOutcome:   domain.DecisionDeny,
			wantReasonSub: "CVSS score 9.0",
			wantDenyCount: 2,
		},
		{
			name: "empty metadata with CVSS policy, no match",
			req: domain.AccessRequest{
				TenantID: "tenant-1",
				Artifact: domain.ArtifactIdentity{
					Ecosystem: domain.EcosystemNPM,
					Namespace: "public",
					Name:      "safe-package",
					Version:   "2.0.0",
				},
				Metadata:  nil,
				Timestamp: now,
			},
			policies: []domain.Policy{
				{
					ID: "p1", TenantID: "tenant-1", Name: "block-high-cvss",
					Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionDeny,
					Config: &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)}, Priority: 0, Enabled: true,
				},
			},
			wantOutcome:   domain.DecisionAllow,
			wantReasonSub: "no matching policy",
		},
	}

	eval := NewEvaluator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := eval.Evaluate(tt.req, tt.policies)

			assert.Equal(t, tt.wantOutcome, decision.Outcome)
			assert.Contains(t, decision.Reason, tt.wantReasonSub)
			assert.Equal(t, tt.req.TenantID, decision.TenantID)

			if tt.wantDenyCount > 0 {
				denyCount := 0
				for _, r := range decision.Reasons {
					if r.Action == domain.PolicyActionDeny {
						denyCount++
					}
				}
				assert.Equal(t, tt.wantDenyCount, denyCount, "deny reason count")
			}

			if tt.wantAllowCount > 0 {
				allowCount := 0
				for _, r := range decision.Reasons {
					if r.Action == domain.PolicyActionAllow {
						allowCount++
					}
				}
				assert.Equal(t, tt.wantAllowCount, allowCount, "allow reason count")
			}
		})
	}
}

func TestEvaluate_SamePriorityDeterministic(t *testing.T) {
	now := time.Now()
	req := domain.AccessRequest{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "untrusted-registry",
			Name:      "some-package",
			Version:   "1.0.0",
		},
		Metadata: &domain.ArtifactMetadata{
			MaxCVSS: ptrFloat64(9.0),
		},
		Timestamp: now,
	}

	policies := []domain.Policy{
		{
			ID:       "p2",
			TenantID: "tenant-1",
			Name:     "block-untrusted",
			Type:     domain.PolicyTypeBlocklist,
			Action:   domain.PolicyActionDeny,
			Config: &domain.NamespaceListPolicyConfig{
				Namespaces: []string{"untrusted-registry"},
			},
			Priority: 0,
			Enabled:  true,
		},
		{
			ID: "p1", TenantID: "tenant-1", Name: "block-high-cvss",
			Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionDeny,
			Config: &domain.CVSSThresholdPolicyConfig{MaxCVSS: ptrFloat64(7.0)}, Priority: 0, Enabled: true,
		},
	}

	eval := NewEvaluator()

	// Run multiple times to verify determinism.
	for i := range 20 {
		decision := eval.Evaluate(req, policies)
		assert.Equal(t, domain.DecisionDeny, decision.Outcome)
		// "block-high-cvss" sorts before "block-untrusted" alphabetically,
		// so its deny reason should always be the first.
		assert.Contains(t, decision.Reason, "CVSS score 9.0",
			"iteration %d: first deny reason should always be from block-high-cvss", i)
	}
}

func TestEvaluate_UnknownPolicyType(t *testing.T) {
	now := time.Now()
	req := domain.AccessRequest{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "public",
			Name:      "safe-package",
			Version:   "1.0.0",
		},
		Metadata:  &domain.ArtifactMetadata{},
		Timestamp: now,
	}

	policies := []domain.Policy{
		{
			ID: "p1", TenantID: "tenant-1", Name: "bad-policy",
			Type: domain.PolicyType("nonexistent_type"), Action: domain.PolicyActionDeny,
			Config: &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}}, Priority: 0, Enabled: true,
		},
	}

	eval := NewEvaluator()
	decision := eval.Evaluate(req, policies)

	assert.Equal(t, domain.DecisionDeny, decision.Outcome)
	assert.Contains(t, decision.Reason, "unknown policy type")

	// Should have exactly one reason with evaluation_error category.
	assert.Len(t, decision.Reasons, 1)
	assert.Equal(t, domain.ReasonCategoryEvaluationError, decision.Reasons[0].Category)
	assert.Equal(t, domain.PolicyActionDeny, decision.Reasons[0].Action)
}

func TestEvaluate_ConditionEvaluationError(t *testing.T) {
	now := time.Now()
	req := domain.AccessRequest{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "public",
			Name:      "some-package",
			Version:   "1.0.0",
		},
		Metadata: &domain.ArtifactMetadata{
			MaxCVSS: ptrFloat64(5.0),
		},
		Timestamp: now,
	}

	// Mismatched config type should cause evaluation error.
	policies := []domain.Policy{
		{
			ID: "p1", TenantID: "tenant-1", Name: "bad-config-policy",
			Type: domain.PolicyTypeCVSSThreshold, Action: domain.PolicyActionAllow,
			Config: &domain.NamespaceListPolicyConfig{Namespaces: []string{"internal"}}, Priority: 0, Enabled: true,
		},
	}

	eval := NewEvaluator()
	decision := eval.Evaluate(req, policies)

	assert.Equal(t, domain.DecisionDeny, decision.Outcome)
	assert.Contains(t, decision.Reason, "condition evaluation error")

	// Should have evaluation_error category reason.
	var hasEvalError bool
	for _, r := range decision.Reasons {
		if r.Category == domain.ReasonCategoryEvaluationError {
			hasEvalError = true
			break
		}
	}
	assert.True(t, hasEvalError, "should contain evaluation_error reason")
}

func TestEvaluate_WarnMode(t *testing.T) {
	now := time.Now()
	oldPublish := now.Add(-400 * 24 * time.Hour)

	req := domain.AccessRequest{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "old-but-stable",
			Version:   "1.0.0",
		},
		Metadata: &domain.ArtifactMetadata{
			PublishedAt: &oldPublish,
		},
		Timestamp: now,
	}

	policies := []domain.Policy{
		{
			ID: "p1", TenantID: "tenant-1", Name: "block-old-warn",
			Type: domain.PolicyTypeMaximumAge, Action: domain.PolicyActionDeny,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365), DryRun: true},
			Priority: 10, Enabled: true,
		},
	}

	eval := NewEvaluator()
	decision := eval.Evaluate(req, policies)

	// Warn mode should NOT block the package.
	assert.Equal(t, domain.DecisionAllow, decision.Outcome)

	// Should have a warning.
	assert.Len(t, decision.Warnings, 1)
	assert.Contains(t, decision.Warnings[0], "block-old-warn")
	assert.Contains(t, decision.Warnings[0], "maximum allowed is 365 days")

	// Reason should be recorded with warning category.
	var hasWarning bool
	for _, r := range decision.Reasons {
		if r.Category == domain.ReasonPolicyWarning {
			hasWarning = true
			break
		}
	}
	assert.True(t, hasWarning, "should contain policy_warning reason")
}

func TestEvaluate_WarnModeDoesNotOverrideDeny(t *testing.T) {
	now := time.Now()
	oldPublish := now.Add(-400 * 24 * time.Hour)

	req := domain.AccessRequest{
		TenantID: "tenant-1",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Namespace: "evil-corp",
			Name:      "bad-pkg",
			Version:   "1.0.0",
		},
		Metadata: &domain.ArtifactMetadata{
			PublishedAt: &oldPublish,
		},
		Timestamp: now,
	}

	policies := []domain.Policy{
		{
			ID: "p1", TenantID: "tenant-1", Name: "block-old-warn",
			Type: domain.PolicyTypeMaximumAge, Action: domain.PolicyActionDeny,
			Config:   &domain.MaximumAgePolicyConfig{MaxAgeDays: ptrInt(365), DryRun: true},
			Priority: 10, Enabled: true,
		},
		{
			ID: "p2", TenantID: "tenant-1", Name: "block-evil",
			Type: domain.PolicyTypeBlocklist, Action: domain.PolicyActionDeny,
			Config:   &domain.NamespaceListPolicyConfig{Namespaces: []string{"evil-corp"}},
			Priority: 20, Enabled: true,
		},
	}

	eval := NewEvaluator()
	decision := eval.Evaluate(req, policies)

	// The blocklist deny should still block.
	assert.Equal(t, domain.DecisionDeny, decision.Outcome)
	assert.Contains(t, decision.Reason, "blocked")

	// Should still have the warning from the warn-mode policy.
	assert.Len(t, decision.Warnings, 1)
}
